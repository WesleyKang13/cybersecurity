<?php

declare(strict_types=1);

namespace App\Services;

use App\Jobs\RetryEmailAnalysisJob;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Models\WhitelistedDomain;
use App\Support\GeminiAnalysisException;
use App\Support\GmailAuthenticationEvidence;
use App\Support\GeminiResponseValidator;
use App\Support\VirusTotalScanResult;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;

class EmailScannerService
{
    private const MAX_PROMPT_BODY_CHARS = 6000;
    private const MAX_EXTRACTED_LINKS = 25;
    private const MAX_EXTRACTED_URLS = 50;
    private const MAX_URL_SCAN_TEXT_CHARS = 200000;
    private const MAX_RETRY_PDF_BASE64_CHARS = 1400000;
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const REQUEST_TIMEOUT_SECONDS = 10;

    protected GeminiResponseValidator $geminiValidator;

    public function __construct(protected VirusTotalService $virusTotalService, ?GeminiResponseValidator $geminiValidator = null)
    {
        $this->geminiValidator = $geminiValidator ?? app(GeminiResponseValidator::class);
    }

    public function scanAndStore(User $user, array $email): array
    {
        $messageId = (string) ($email['google_message_id'] ?? '');
        $identity = ['user_id' => $user->id, 'google_message_id' => $messageId];
        $existing = ScannedEmail::withTrashed()
            ->where($identity)
            ->first();

        if ($existing && ($existing->trashed() || $existing->analysis_status === 'completed')) {
            return ['record' => $existing, 'created' => false];
        }

        $input = $this->prepareInput($email);
        $record = $existing ?? ScannedEmail::withTrashed()->createOrFirst($identity, $this->pendingAttributes($input));
        $created = $record->wasRecentlyCreated;

        if (! $created && ($record->trashed() || $record->analysis_status === 'completed')) {
            return ['record' => $record, 'created' => false];
        }

        if ($this->claim($record, $identity)) {
            $record->refresh();
            $this->analyzeClaimed($user, $record, $input);
            $record->refresh();
        }

        if ($created) {
            // Preserve the historical API shape for a just-inserted database default.
            $record->setAttribute('is_quarantined', null);
        }

        return ['record' => $record, 'created' => $created];
    }

    public function retryIncomplete(User $user, string $messageId): ?ScannedEmail
    {
        $identity = ['user_id' => $user->id, 'google_message_id' => $messageId];
        $record = ScannedEmail::withTrashed()->where($identity)->first();

        if ($record === null || $record->trashed() || $record->analysis_status === 'completed' || ! is_array($record->analysis_retry_payload)) {
            return $record;
        }

        if (! $this->claim($record, $identity, true)) {
            return $record;
        }

        $record->refresh();
        $this->analyzeClaimed($user, $record, $record->analysis_retry_payload);

        return $record->fresh();
    }

    public function formatResult(ScannedEmail $record, bool $created): array
    {
        return [
            'id' => $record->id,
            'google_message_id' => $record->google_message_id,
            'subject' => $record->subject,
            'sender' => $record->sender,
            'snippet' => $record->snippet,
            'is_threat' => $record->is_threat,
            'severity' => $record->severity,
            'risk_score' => $record->risk_score,
            'reason' => $record->final_reasoning ?? $record->reason,
            'verdict' => $record->verdict,
            'threat_category' => $record->threat_category,
            'analysis_chain' => $record->analysis_chain ?? [],
            'final_reasoning' => $record->final_reasoning,
            'origin_trace' => $record->origin_trace,
            'detection_layer' => $record->detection_layer,
            'is_quarantined' => $record->is_quarantined,
            'analysis_status' => $record->analysis_status,
            'analysis_attempts' => $record->analysis_attempts,
            'analysis_next_retry_at' => $record->analysis_next_retry_at?->toIso8601String(),
            'created' => $created,
        ];
    }

    /** @return array<string, mixed> */
    private function prepareInput(array $email): array
    {
        $subject = trim((string) ($email['subject'] ?? 'No Subject'));
        $sender = trim((string) ($email['sender'] ?? 'Unknown'));
        $snippet = trim((string) ($email['snippet'] ?? ''));
        $body = trim((string) ($email['body'] ?? ''));
        $pdfAttachments = array_values(array_map(function (array $attachment): array {
            $base64 = (string) ($attachment['base64_data'] ?? '');

            if (strlen($base64) > self::MAX_RETRY_PDF_BASE64_CHARS) {
                return [
                    'filename' => mb_substr((string) ($attachment['filename'] ?? 'attachment.pdf'), 0, 255),
                    'mime_type' => 'application/pdf',
                    'retry_input_too_large' => true,
                ];
            }

            return [
                'filename' => mb_substr((string) ($attachment['filename'] ?? 'attachment.pdf'), 0, 255),
                'mime_type' => 'application/pdf',
                'base64_data' => $base64,
            ];
        }, array_filter($email['pdf_attachments'] ?? [], fn ($attachment) => is_array($attachment)
            && strtolower((string) ($attachment['mime_type'] ?? '')) === 'application/pdf'
            && ! empty($attachment['base64_data']))));

        return [
            'google_message_id' => (string) ($email['google_message_id'] ?? ''),
            'subject' => mb_substr($subject, 0, 1000),
            'sender' => mb_substr($sender, 0, 1000),
            'snippet' => mb_substr($snippet, 0, self::MAX_PROMPT_BODY_CHARS),
            'body' => mb_substr($body, 0, self::MAX_PROMPT_BODY_CHARS),
            'extracted_links' => $this->normalizeExtractedLinks($email['extracted_links'] ?? []),
            // This encrypted payload is the minimum retry input. Raw headers and OAuth
            // credentials are never stored; PDF bytes are cleared on completion.
            'pdf_attachments' => array_slice($pdfAttachments, 0, 5),
            'gmail_authentication' => $email['gmail_authentication'] ?? null,
        ];
    }

    /** @param array<string, mixed> $input */
    private function pendingAttributes(array $input): array
    {
        return [
            'subject' => $input['subject'],
            'sender' => $input['sender'],
            'snippet' => $input['snippet'] !== '' ? $input['snippet'] : $input['body'],
            'is_threat' => false,
            'detection_layer' => 'Layer 3 (Analysis Pending)',
            'severity' => 'inconclusive',
            'risk_score' => 1,
            'reason' => 'Analysis is pending.',
            'verdict' => 'INCONCLUSIVE',
            'threat_category' => 'None',
            'analysis_chain' => ['Analysis has not completed yet.'],
            'final_reasoning' => 'Analysis is pending.',
            'analysis_status' => 'retry_pending',
            'analysis_attempts' => 0,
            'analysis_retry_payload' => $this->retryPayload($input),
        ];
    }

    /** @param array<string, mixed> $input */
    private function retryPayload(array $input): array
    {
        unset($input['gmail_authentication']);

        return $input;
    }

    /** @param array<string, mixed> $identity */
    private function claim(ScannedEmail $record, array $identity, bool $fromQueue = false): bool
    {
        $now = now();
        $leaseToken = (string) Str::uuid();
        $query = ScannedEmail::where('id', $record->id)->where($identity)->whereNull('deleted_at');

        if ($fromQueue) {
            // The delayed job is the scheduler. Allowing an explicitly invoked
            // retry also makes recovery possible after a queue clock skew.
            $query->where('analysis_status', 'retry_pending');
        } else {
            $query->where(function ($claimable) use ($now) {
                $claimable->whereIn('analysis_status', ['retry_pending', 'failed'])
                    ->orWhere(function ($stale) use ($now) {
                        $stale->where('analysis_status', 'processing')
                            ->where('analysis_lease_expires_at', '<=', $now);
                    });
            });
        }

        return $query->update([
            'analysis_status' => 'processing',
            'analysis_attempts' => $record->analysis_attempts + 1,
            'analysis_last_attempted_at' => $now,
            'analysis_next_retry_at' => null,
            'analysis_lease_token' => $leaseToken,
            'analysis_lease_expires_at' => $now->copy()->addSeconds((int) config('services.gemini.lease_seconds', 120)),
        ]) === 1;
    }

    /** @param array<string, mixed> $input */
    private function analyzeClaimed(User $user, ScannedEmail $record, array $input): void
    {
        $messageBody = $input['body'] !== '' ? $input['body'] : $input['snippet'];
        $extractedLinks = $this->normalizeExtractedLinks($input['extracted_links'] ?? []);
        $pdfAttachments = $input['pdf_attachments'] ?? [];
        $extractedUrls = $this->buildExtractedUrls(trim($input['snippet'].' '.$messageBody), $extractedLinks);
        $analysis = $this->runSecurityFunnel(
            subject: $input['subject'],
            snippet: $input['snippet'],
            messageBody: $messageBody,
            sender: $input['sender'],
            senderDomain: $this->extractSenderDomain($input['sender']),
            extractedUrls: $extractedUrls,
            extractedLinks: $extractedLinks,
            pdfAttachments: $pdfAttachments,
            gmailAuthentication: $input['gmail_authentication'] ?? null
        );

        $identity = ['id' => $record->id, 'user_id' => $user->id, 'google_message_id' => $record->google_message_id, 'analysis_lease_token' => $record->analysis_lease_token];
        $attributes = $this->analysisAttributes($analysis);

        if (($analysis['analysis_status'] ?? 'completed') === 'completed') {
            ScannedEmail::where($identity)->update(array_merge($attributes, [
                'analysis_status' => 'completed',
                'analysis_completed_at' => now(),
                'analysis_last_error_code' => null,
                'analysis_next_retry_at' => null,
                'analysis_lease_token' => null,
                'analysis_lease_expires_at' => null,
                'analysis_retry_payload' => null,
            ]));

            return;
        }

        $this->persistIncomplete($record, $user, $attributes, (string) $analysis['analysis_last_error_code'], (bool) $analysis['retryable']);
    }

    /** @param array<string, mixed> $analysis @return array<string, mixed> */
    private function analysisAttributes(array $analysis): array
    {
        return array_intersect_key($analysis, array_flip([
            'is_threat', 'detection_layer', 'severity', 'risk_score', 'reason', 'verdict',
            'threat_category', 'analysis_chain', 'final_reasoning',
        ]));
    }

    /** @param array<string, mixed> $attributes */
    private function persistIncomplete(ScannedEmail $record, User $user, array $attributes, string $errorCode, bool $retryable): void
    {
        $maxAttempts = (int) config('services.gemini.max_analysis_attempts', 3);
        $canRetry = $retryable && $record->analysis_attempts < $maxAttempts;
        $nextRetry = $canRetry ? now()->addSeconds($this->retryDelay($record->analysis_attempts)) : null;
        $status = $canRetry ? 'retry_pending' : 'failed';
        $errorCode = $canRetry ? $errorCode : ($retryable ? 'retry_exhausted' : $errorCode);
        $updated = ScannedEmail::where([
            'id' => $record->id,
            'user_id' => $user->id,
            'google_message_id' => $record->google_message_id,
            'analysis_lease_token' => $record->analysis_lease_token,
        ])->update(array_merge($attributes, [
            'analysis_status' => $status,
            'analysis_last_error_code' => $errorCode,
            'analysis_next_retry_at' => $nextRetry,
            'analysis_lease_token' => null,
            'analysis_lease_expires_at' => null,
        ]));

        if ($updated === 1 && $canRetry) {
            RetryEmailAnalysisJob::dispatch($user->id, $record->google_message_id)->delay($nextRetry);
        }
    }

    private function retryDelay(int $attempt): int
    {
        $delays = config('services.gemini.retry_delays', [60, 300, 900]);
        $base = (int) ($delays[min(max($attempt - 1, 0), count($delays) - 1)] ?? 900);

        return $base + random_int(0, min(15, max(1, intdiv($base, 10))));
    }

    private function runSecurityFunnel(
        string $subject,
        string $snippet,
        string $messageBody,
        string $sender,
        ?string $senderDomain,
        array $extractedUrls,
        array $extractedLinks,
        array $pdfAttachments,
        mixed $gmailAuthentication
    ): array {
        $whitelist = Cache::remember('trusted_domains', 3600, function () {
            return WhitelistedDomain::where('is_active', true)
                ->pluck('domain')
                ->toArray();
        });

        $whitelistTrust = $this->assessWhitelistTrust($senderDomain, $whitelist, $gmailAuthentication);
        $decisionTrace = $this->initialDecisionTrace($senderDomain, $whitelistTrust);

        $subjectLower = strtolower($subject);
        $snippetLower = strtolower($snippet);
        $bodyLower = strtolower($messageBody);
        $fullText = trim($subjectLower . ' ' . $snippetLower . ' ' . $bodyLower);
        $heuristicFlags = [];
        $heuristicSignals = [];

        $suspiciousTlds = ['.xyz', '.top', '.click', '.buzz', '.monster', '.cc', '.su', '.ru'];
        foreach ($suspiciousTlds as $tld) {
            if ($senderDomain !== null && str_ends_with($senderDomain, $tld)) {
                if ($whitelistTrust['matched']) {
                    $decisionTrace[] = 'decision:whitelist_benefit=overridden_suspicious_tld';
                }
                $decisionTrace[] = 'decision:layer_2.heuristics=terminal_suspicious_tld';
                $decisionTrace[] = 'decision:layer_2_5.virustotal=skipped_heuristic_terminal';
                $decisionTrace[] = 'decision:attachment_analysis=skipped_heuristic_terminal';
                $decisionTrace[] = 'decision:layer_3.gemini=skipped_heuristic_terminal';

                return $this->withDecisionTrace($this->buildAnalysisResult(
                    detectionLayer: 'Layer 2 (Heuristics)',
                    riskScore: 95,
                    verdict: 'MALICIOUS',
                    threatCategory: 'Phishing',
                    analysisChain: [
                        "Sender domain '{$senderDomain}' ends with the suspicious TLD '{$tld}'.",
                        'The sender identity carries elevated impersonation and social engineering risk.',
                        'The message was blocked before VirusTotal or Gemini needed to decide the outcome.',
                    ],
                    finalReasoning: "The message was flagged as malicious because the sender domain '{$senderDomain}' uses the high-risk TLD '{$tld}', which strongly correlates with phishing infrastructure.",
                    severity: 'high',
                    isThreat: true
                ), $decisionTrace);
            }
        }

        $publicProviders = [
            'gmail.com',
            'yahoo.com',
            'hotmail.com',
            'outlook.com',
            'aol.com',
            'icloud.com',
            'proton.me',
            'mail.com',
        ];

        $decisionTrace[] = 'decision:layer_2.heuristics=ran';

        if ($senderDomain !== null && in_array($senderDomain, $publicProviders, true)) {
            $urgentKeywords = [
                'urgent',
                'suspend',
                'immediate action',
                'password reset',
                'invoice',
                'verify your account',
                'unauthorized login',
                'account limited',
                'final notice',
                'document attached',
            ];

            foreach ($urgentKeywords as $keyword) {
                if (str_contains($fullText, $keyword)) {
                    $heuristicFlags[] = "Urgent keyword found: '{$keyword}' from public provider '{$senderDomain}'.";
                }
            }

            $impersonatedBrands = ['paypal', 'amazon', 'apple', 'microsoft', 'netflix', 'meta', 'facebook', 'bank', 'support'];
            foreach ($impersonatedBrands as $brand) {
                if (str_contains($subjectLower, $brand)) {
                    $heuristicFlags[] = "Impersonated brand found: '{$brand}' in subject from public provider '{$senderDomain}'.";
                }
            }
        }

        $scamPhrases = [
            'bitcoin giveaway',
            'wallet validation',
            'seed phrase',
            'guaranteed return',
            'i have recorded you',
            'webcam hacked',
            'pay me in bitcoin',
            'transfer funds immediately',
        ];

        foreach ($scamPhrases as $phrase) {
            if (str_contains($fullText, strtolower($phrase))) {
                $heuristicFlags[] = "Known scam phrase detected: '{$phrase}'.";
            }
        }

        $this->addBecEscalationSignals($fullText, $heuristicFlags, $heuristicSignals);

        $vtResult = empty($extractedUrls)
            ? VirusTotalScanResult::skippedNoUrl()
            : $this->virusTotalService->inspectFirstUrl($extractedUrls);
        $vtContext = $this->buildVirusTotalContext($vtResult, $extractedUrls);
        $decisionTrace[] = 'decision:layer_2_5.virustotal='.$vtResult->status;

        if ($vtResult->vendorFlagCount() >= 3) {
            $decisionTrace[] = 'decision:whitelist_benefit=overridden_technical_threat';
            $decisionTrace[] = 'decision:attachment_analysis=skipped_technical_threat';
            $decisionTrace[] = 'decision:layer_3.gemini=skipped_technical_threat';

            return $this->withDecisionTrace($this->buildAnalysisResult(
                detectionLayer: 'Layer 2.5 (VirusTotal API)',
                riskScore: 100,
                verdict: 'MALICIOUS',
                threatCategory: 'Malware',
                analysisChain: [
                    "The sender '{$sender}' was not cleared by the whitelist or heuristic layers.",
                    'The content advanced to technical validation because it contained a URL requiring deeper inspection.',
                    "VirusTotal reported {$vtContext['vendor_flag_count']} independent vendor flags for {$vtContext['scanned_url']}, exceeding the confirmation threshold.",
                ],
                finalReasoning: "The message was classified as malicious because VirusTotal reported {$vtContext['vendor_flag_count']} vendor detections for {$vtContext['scanned_url']}, which exceeds the 3-vendor threshold for a confirmed technical threat.",
                severity: 'high',
                isThreat: true
            ), $decisionTrace);
        }

        $financialContext = $this->analyzeFinancialAttachments($pdfAttachments);
        $decisionTrace[] = empty($pdfAttachments)
            ? 'decision:attachment_analysis=skipped_no_pdf'
            : 'decision:attachment_analysis=ran';
        $financialFailure = collect($financialContext)->first(fn (array $result) => ($result['analysis_incomplete'] ?? false) === true);

        if ($financialFailure !== null) {
            $decisionTrace[] = 'decision:attachment_analysis=incomplete';
            $decisionTrace[] = 'decision:layer_3.gemini=skipped_attachment_incomplete';

            return $this->withDecisionTrace($this->buildIncompleteResult(
                (string) $financialFailure['error_code'],
                (bool) $financialFailure['retryable']
            ), $decisionTrace);
        }
        $paymentRequestContext = array_values(array_filter($financialContext, function ($result) {
            return ($result['is_payment_request'] ?? false) === true;
        }));

        $deterministicOverride = $this->deterministicWhitelistOverride(
            heuristicFlags: $heuristicFlags,
            heuristicSignals: $heuristicSignals,
            extractedLinks: $extractedLinks,
            pdfAttachments: $pdfAttachments,
            paymentRequests: $paymentRequestContext
        );
        $geminiReasons = $this->geminiEscalationReasons(
            deterministicOverride: $deterministicOverride,
            heuristicSignals: $heuristicSignals,
            extractedUrls: $extractedUrls,
            virusTotalResult: $vtResult
        );

        if ($whitelistTrust['accepted'] && empty($geminiReasons)) {
            $decisionTrace[] = 'decision:layer_3.gemini=skipped_verified_whitelist_clean';

            return $this->withDecisionTrace($this->buildAnalysisResult(
                detectionLayer: 'Layer 1 (Verified Whitelist)',
                riskScore: 0,
                verdict: 'SAFE',
                threatCategory: 'None',
                analysisChain: [
                    'Verified sender authentication and whitelist policy passed.',
                    'Applicable deterministic heuristic, URL, and attachment checks completed without an escalation signal.',
                    'Contextual Gemini analysis was skipped after the clean deterministic scan.',
                ],
                finalReasoning: 'The sender matched the whitelist and Gmail verified aligned DMARC, SPF, and DKIM passes; deterministic checks completed without an escalation signal.',
                severity: 'clean',
                isThreat: false
            ), $decisionTrace);
        }

        if (! empty($geminiReasons) && $whitelistTrust['matched']) {
            foreach ($geminiReasons as $reason) {
                $decisionTrace[] = "decision:whitelist_benefit=overridden_{$reason}";
            }
        }
        foreach ($geminiReasons as $reason) {
            $decisionTrace[] = "decision:gemini_trigger={$reason}";
        }
        $decisionTrace[] = $whitelistTrust['accepted'] && ! empty($geminiReasons)
            ? "decision:layer_3.gemini=called_{$geminiReasons[0]}"
            : 'decision:layer_3.gemini=called_normal_policy';

        return $this->withDecisionTrace($this->analyzeWithGemini(
            subject: $subject,
            sender: $sender,
            messageBody: $messageBody,
            extractedUrls: $extractedUrls,
            extractedLinks: $extractedLinks,
            vtContext: $vtContext,
            financialContext: $paymentRequestContext,
            heuristicFlags: $heuristicFlags
        ), $decisionTrace);
    }

    private function analyzeWithGemini(
        string $subject,
        string $sender,
        string $messageBody,
        array $extractedUrls,
        array $extractedLinks,
        array $vtContext,
        array $financialContext,
        array $heuristicFlags
    ): array {
        if ($this->isMockMode()) {
            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 3 (Mock AI)',
                riskScore: 10,
                verdict: 'SAFE',
                threatCategory: 'None',
                analysisChain: [
                    "Sender '{$this->extractSenderEmail($sender)}' was passed into mock analysis mode.",
                    'Mock mode does not simulate malicious financial or psychological intent.',
                    'VirusTotal and financial attachment metadata, if present, were ignored because mock mode short-circuits the live AI call.',
                ],
                finalReasoning: 'Mock scan: Email content appears safe.'
            );
        }

        $apiKey = config('services.gemini.key');
        if (empty($apiKey)) {
            Log::warning('Gemini API key is missing while AI mode is live.');

            return $this->buildIncompleteResult('missing_api_key', false);
        }

        $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}";
        $senderEmail = $this->extractSenderEmail($sender);

        $prompt = <<<PROMPT
You are an elite cybersecurity consensus agent. Your objective is to analyze incoming emails and SMS messages for Business Email Compromise (BEC), phishing, and malware, outputting a highly accurate threat assessment in strict JSON format.

You will receive the message content and metadata from secondary scanning layers (e.g., VirusTotal). You must weigh both the technical data and the psychological intent of the message.

---
### INPUT DATA
- Sender Identity: {$this->jsonPromptValue($senderEmail)}
- Message Subject: {$this->jsonPromptValue($subject)}
- Message Body: {$this->jsonPromptValue(mb_substr($messageBody, 0, self::MAX_PROMPT_BODY_CHARS))}
- Extracted URLs: {$this->jsonPromptValue($extractedUrls)}
- Extracted Link Details: {$this->jsonPromptValue($extractedLinks)}
- VirusTotal Layer 2.5 Results: {$this->jsonPromptValue($vtContext)}
- Financial Attachment Context: {$this->jsonPromptValue($financialContext)}
- Layer 2 Heuristic Flags: {$this->jsonPromptValue($heuristicFlags)}

---
### ANALYSIS RULES

1. EVALUATE BEC & INTENT (The Trust Factor):
- Scrutinize the message for urgency, secrecy, or requests to bypass standard procedures.
- Flag high-risk financial requests: altering payroll routing, changing vendor bank details, urgent wire transfers, or purchasing gift cards.
- Compare the sender's email domain against the claimed identity. Look for typosquatting (e.g., @rnicrosoft.com instead of @microsoft.com).

2. HANDLE TECHNICAL NOISE (The VirusTotal Threshold):
- If VirusTotal reports 1 to 2 vendor flags on a URL belonging to a known cybersecurity, educational, or technology platform, treat this as vendor noise/false positive. Do not classify the message as malicious based solely on low-threshold VT hits.
- A URL requires 3 or more independent vendor flags to be considered a confirmed technical threat.

3. ESTABLISH TRUST THROUGH REASONING:
- Inspect the extracted link details for destination-domain mismatches, deceptive anchor text, and shortened URLs that resolve to unrelated destinations.
- Treat the Layer 2 heuristic flags as social-engineering indicators, not automatic proof of compromise. Weigh them against the financial attachment context and VirusTotal evidence before deciding the final verdict.
- Your verdict must be defensible. You must provide a concise, technical explanation of exactly why a threat was flagged or why it was deemed safe.

---
### OUTPUT REQUIREMENTS
You must respond ONLY with a valid JSON object matching the exact structure below. Do not include markdown formatting, backticks, or conversational text outside the JSON.

{
  "risk_score": <int 0-100>,
  "verdict": "<SAFE | SUSPICIOUS | MALICIOUS>",
  "threat_category": "<None | BEC/Invoice Fraud | Phishing | Malware | False Positive Noise>",
  "analysis_chain": [
    "<Step 1: Evaluate sender identity and domain>",
    "<Step 2: Evaluate financial or psychological intent>",
    "<Step 3: Contextualize VirusTotal metadata>"
  ],
  "final_reasoning": "<A 2-3 sentence technical explanation for the admin dashboard justifying the verdict.>"
}
PROMPT;

        try {
            $result = $this->geminiValidator->validateEmail($this->requestGemini($url, [
                'contents' => [['parts' => [['text' => $prompt]]]],
                'generationConfig' => [
                    'responseMimeType' => 'application/json',
                    'temperature' => 0.1,
                ],
                'safetySettings' => [
                    ['category' => 'HARM_CATEGORY_HARASSMENT', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_HATE_SPEECH', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold' => 'BLOCK_NONE'],
                ],
            ]));

            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 3 (AI Analysis)',
                riskScore: (int) ($result['risk_score'] ?? 0),
                verdict: (string) ($result['verdict'] ?? 'SAFE'),
                threatCategory: (string) ($result['threat_category'] ?? 'None'),
                analysisChain: is_array($result['analysis_chain'] ?? null) ? $result['analysis_chain'] : [],
                finalReasoning: (string) ($result['final_reasoning'] ?? 'AI verification complete.')
            );
        } catch (GeminiAnalysisException $e) {
            Log::warning('Gemini email analysis incomplete.', ['code' => $e->errorCode]);

            return $this->buildIncompleteResult($e->errorCode, $e->retryable);
        } catch (\Throwable $e) {
            Log::warning('Gemini email analysis failed unexpectedly.', ['exception' => get_class($e)]);

            return $this->buildIncompleteResult('network_error', true);
        }
    }

    private function analyzeFinancialAttachments(array $pdfAttachments): array
    {
        if (empty($pdfAttachments)) {
            return [];
        }

        return array_values(array_map(function (array $attachment) {
            return $this->analyzeFinancialPdfAttachment($attachment);
        }, $pdfAttachments));
    }

    private function analyzeFinancialPdfAttachment(array $attachment): ?array
    {
        if (($attachment['retry_input_too_large'] ?? false) === true) {
            return $this->incompleteAttachment('attachment_too_large', false);
        }

        $prompt = <<<PROMPT
You are a Financial Security Agent. Your job is to extract payment instructions from the provided invoice/document.
Return ONLY a JSON object with the following structure:
{
  "vendor_name": "<Extracted name or null>",
  "invoice_amount": "<Extracted amount or null>",
  "bank_routing_number": "<Extracted routing/sort code or null>",
  "bank_account_number": "<Extracted account number or null>",
  "is_payment_request": <boolean>
}
PROMPT;

        if ($this->isMockMode()) {
            return [
                'attachment_name' => $attachment['filename'] ?? null,
                'vendor_name' => null,
                'invoice_amount' => null,
                'bank_routing_number' => null,
                'bank_account_number' => null,
                'is_payment_request' => false,
            ];
        }

        $apiKey = config('services.gemini.key');
        if (empty($apiKey)) {
            Log::warning('Gemini API key is missing while financial PDF analysis is live.');
            return $this->incompleteAttachment('missing_api_key', false);
        }

        try {
            $result = $this->geminiValidator->validateFinancialAttachment($this->requestGemini(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}",
                [
                    'contents' => [[
                        'parts' => [
                            ['text' => $prompt],
                            ['inlineData' => ['mimeType' => 'application/pdf', 'data' => (string) $attachment['base64_data']]],
                        ],
                    ]],
                    'generationConfig' => ['responseMimeType' => 'application/json', 'temperature' => 0.1],
                ]
            ));

            return [
                'attachment_name' => $attachment['filename'] ?? null,
                ...$result,
            ];
        } catch (GeminiAnalysisException $e) {
            Log::warning('Gemini financial attachment analysis incomplete.', ['code' => $e->errorCode]);

            return $this->incompleteAttachment($e->errorCode, $e->retryable);
        } catch (\Throwable $e) {
            Log::warning('Gemini financial attachment analysis failed unexpectedly.', ['exception' => get_class($e)]);

            return $this->incompleteAttachment('network_error', true);
        }
    }

    /** @return array{attachment_name: null, analysis_incomplete: true, error_code: string, retryable: bool} */
    private function incompleteAttachment(string $errorCode, bool $retryable): array
    {
        return [
            'attachment_name' => null,
            'analysis_incomplete' => true,
            'error_code' => $errorCode,
            'retryable' => $retryable,
        ];
    }

    /** @param array<string, mixed> $payload @return array<string, mixed> */
    private function requestGemini(string $url, array $payload): array
    {
        $limit = max(1, (int) config('services.gemini.requests_per_minute', 4));
        $response = RateLimiter::attempt('gemini-api:provider', $limit, function () use ($url, $payload) {
            try {
                return Http::withHeaders(['Content-Type' => 'application/json'])
                    ->connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                    ->timeout(self::REQUEST_TIMEOUT_SECONDS)
                    ->post($url, $payload);
            } catch (\Illuminate\Http\Client\ConnectionException $e) {
                throw new GeminiAnalysisException('network_error', true, 'Gemini network request failed.');
            }
        }, 60);

        if ($response === false) {
            throw new GeminiAnalysisException('rate_limited', true, 'Gemini provider rate limit is exhausted.');
        }

        if (! $response instanceof \Illuminate\Http\Client\Response) {
            throw new GeminiAnalysisException('network_error', true, 'Gemini provider did not return a response.');
        }

        if ($response->successful()) {
            $providerPayload = $response->json();

            if (! is_array($providerPayload)) {
                throw new GeminiAnalysisException('invalid_response', true, 'Gemini provider returned a non-object response.');
            }

            return $providerPayload;
        }

        $status = $response->status();
        if ($status === 408) {
            throw new GeminiAnalysisException('timeout', true, 'Gemini request timed out.');
        }
        if ($status === 429) {
            throw new GeminiAnalysisException('rate_limited', true, 'Gemini provider rate limited the request.');
        }
        if ($status >= 500) {
            throw new GeminiAnalysisException('provider_5xx', true, 'Gemini provider failed.');
        }
        if (in_array($status, [401, 403], true)) {
            throw new GeminiAnalysisException('provider_auth_error', false, 'Gemini credentials were rejected.');
        }
        if ($status === 400) {
            throw new GeminiAnalysisException('invalid_request', false, 'Gemini rejected the request.');
        }

        throw new GeminiAnalysisException('provider_error', false, 'Gemini returned a permanent error.');
    }

    /** @return array<string, mixed> */
    private function buildIncompleteResult(string $errorCode, bool $retryable): array
    {
        $status = $retryable ? 'retry_pending' : 'failed';
        $message = $retryable ? 'Analysis is incomplete and will be retried.' : 'Analysis is unavailable and requires a later retry.';

        return [
            'is_threat' => false,
            'detection_layer' => 'Layer 3 (Analysis Incomplete)',
            'severity' => 'inconclusive',
            'risk_score' => 1,
            'reason' => $message,
            'verdict' => 'INCONCLUSIVE',
            'threat_category' => 'None',
            'analysis_chain' => ['Contextual analysis did not complete.'],
            'final_reasoning' => $message,
            'analysis_status' => $status,
            'analysis_last_error_code' => $errorCode,
            'retryable' => $retryable,
        ];
    }

    private function buildVirusTotalContext(VirusTotalScanResult $vtResult, array $extractedUrls): array
    {
        $vendorFlagCount = $vtResult->vendorFlagCount();

        if ($vendorFlagCount >= 3) {
            $status = 'confirmed_technical_threat';
        } elseif ($vendorFlagCount >= 1) {
            $status = 'below_confirmation_threshold';
        } elseif (in_array($vtResult->status, ['cache_hit_clean', 'api_checked_clean'], true)) {
            $status = 'clean_first_url_only';
        } elseif ($vtResult->status === 'skipped_no_url') {
            $status = 'no_urls_found';
        } else {
            $status = 'inconclusive';
        }

        return [
            'scanned_url' => $vtResult->scannedUrl ?? ($extractedUrls[0] ?? null),
            'vendor_flag_count' => $vendorFlagCount,
            'vendor_flags' => $vtResult->vendorFlags(),
            'status' => $status,
            'lookup_outcome' => $vtResult->status,
            'note' => $vtResult->status === 'skipped_no_url'
                ? 'No URLs were extracted from the message.'
                : 'Only the first extracted URL may be evaluated through VirusTotal to preserve API quota.',
        ];
    }

    /**
     * @param array<int, mixed> $whitelist
     * @return array{matched: bool, accepted: bool, authentication: string, reason: string}
     */
    private function assessWhitelistTrust(?string $senderDomain, array $whitelist, mixed $gmailAuthentication): array
    {
        $matched = $senderDomain !== null && $this->matchesWhitelist($senderDomain, $whitelist);
        $authentication = $this->assessGmailAuthentication($senderDomain, $gmailAuthentication);

        if ($senderDomain === null) {
            return [
                'matched' => false,
                'accepted' => false,
                'authentication' => 'unverified_malformed_sender',
                'reason' => 'sender_domain_malformed',
            ];
        }

        if (! $matched) {
            return [
                'matched' => false,
                'accepted' => false,
                'authentication' => $authentication,
                'reason' => 'not_matched',
            ];
        }

        if ($authentication !== 'verified_aligned_dmarc_spf_dkim') {
            return [
                'matched' => true,
                'accepted' => false,
                'authentication' => $authentication,
                'reason' => "rejected_{$authentication}",
            ];
        }

        return [
            'matched' => true,
            'accepted' => true,
            'authentication' => $authentication,
            'reason' => 'accepted_verified_aligned_dmarc_spf_dkim',
        ];
    }

    /**
     * A whitelist bypass requires all three provider-reported mechanisms to
     * pass and name the visible From domain. This is stricter than DMARC's
     * one-of-SPF-or-DKIM rule by design: a missing, failed, or conflicting
     * mechanism receives no whitelist benefit rather than a trust exception.
     */
    private function assessGmailAuthentication(?string $senderDomain, mixed $gmailAuthentication): string
    {
        if (! $gmailAuthentication instanceof GmailAuthenticationEvidence) {
            return 'unverified_evidence_unavailable';
        }

        if ($gmailAuthentication->dmarcResult !== 'pass') {
            return 'unverified_dmarc_not_pass';
        }

        if ($gmailAuthentication->spfResult !== 'pass') {
            return 'unverified_spf_not_pass';
        }

        if ($gmailAuthentication->dkimResult !== 'pass') {
            return 'unverified_dkim_not_pass';
        }

        $authenticatedDomains = [
            'dmarc' => $this->normalizeDomain($gmailAuthentication->dmarcDomain),
            'spf' => $this->normalizeDomain($gmailAuthentication->spfDomain),
            'dkim' => $this->normalizeDomain($gmailAuthentication->dkimDomain),
        ];

        foreach ($authenticatedDomains as $mechanism => $authenticatedDomain) {
            if ($senderDomain === null || $authenticatedDomain === null || $authenticatedDomain !== $senderDomain) {
                return "unverified_{$mechanism}_misaligned";
            }
        }

        return 'verified_aligned_dmarc_spf_dkim';
    }

    /**
     * A whitelist root intentionally covers its subdomains. The dot boundary
     * prevents a suffix such as trusted.example.attacker.test from matching.
     * Invalid legacy whitelist rows are ignored rather than broadened.
     *
     * @param array<int, mixed> $whitelist
     */
    private function matchesWhitelist(string $senderDomain, array $whitelist): bool
    {
        foreach ($whitelist as $whitelistDomain) {
            $normalizedWhitelistDomain = $this->normalizeDomain((string) $whitelistDomain);

            if ($normalizedWhitelistDomain === null) {
                continue;
            }

            if (
                $senderDomain === $normalizedWhitelistDomain
                || str_ends_with($senderDomain, ".{$normalizedWhitelistDomain}")
            ) {
                return true;
            }
        }

        return false;
    }

    private function extractSenderDomain(string $sender): ?string
    {
        $candidate = trim($sender);

        if (preg_match('/<([^<>]+)>/', $candidate, $matches)) {
            $candidate = trim($matches[1]);
        } elseif (preg_match('/^\s*([^\s<>@]+@[^\s<>@]+)\s*$/', $candidate, $matches)) {
            $candidate = $matches[1];
        } else {
            return null;
        }

        if (! preg_match('/^([^@\s<>]+)@([^@\s<>]+)$/', $candidate, $matches)) {
            return null;
        }

        $localPart = $matches[1];
        $domain = $this->normalizeDomain($matches[2]);

        if ($domain === null || filter_var("{$localPart}@{$domain}", FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }

        return $domain;
    }

    private function normalizeDomain(?string $domain): ?string
    {
        if ($domain === null) {
            return null;
        }

        $normalized = strtolower(trim($domain, " \t\n\r\0\x0B."));

        if ($normalized === '' || str_contains($normalized, '..') || strlen($normalized) > 253) {
            return null;
        }

        if (function_exists('idn_to_ascii')) {
            $asciiDomain = idn_to_ascii($normalized, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($asciiDomain === false) {
                return null;
            }
            $normalized = strtolower($asciiDomain);
        }

        foreach (explode('.', $normalized) as $label) {
            if (
                $label === ''
                || strlen($label) > 63
                || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/', $label) !== 1
            ) {
                return null;
            }
        }

        return $normalized;
    }

    /**
     * @param array<int, string> $heuristicFlags
     * @param array<int, string> $heuristicSignals
     * @param array<int, array<string, mixed>> $extractedLinks
     * @param array<int, array<string, mixed>> $pdfAttachments
     * @param array<int, array<string, mixed>> $paymentRequests
     */
    private function deterministicWhitelistOverride(
        array $heuristicFlags,
        array $heuristicSignals,
        array $extractedLinks,
        array $pdfAttachments,
        array $paymentRequests
    ): ?string {
        if (! empty($heuristicSignals)) {
            return $heuristicSignals[0];
        }

        if (! empty($heuristicFlags)) {
            return 'heuristic_signal';
        }

        foreach ($extractedLinks as $link) {
            if (($link['has_suspicious_mismatch'] ?? false) === true) {
                return 'suspicious_link';
            }
        }

        if (! empty($paymentRequests)) {
            return 'payment_attachment';
        }

        // An attachment requires contextual analysis before whitelist cost control.
        if (! empty($pdfAttachments)) {
            return 'attachment_present';
        }

        return null;
    }

    /**
     * These bounded indicators escalate to contextual analysis only; they do
     * not produce a malicious verdict. Urgency alone is intentionally not a
     * signal, avoiding a fast-path cost increase for routine messages.
     *
     * @param array<int, string> $heuristicFlags
     * @param array<int, string> $heuristicSignals
     */
    private function addBecEscalationSignals(string $fullText, array &$heuristicFlags, array &$heuristicSignals): void
    {
        $hasGiftCardRequest = preg_match('/\b(?:gift[ -]?cards?)\b.{0,80}\b(?:buy|purchase|send|code|codes)\b|\b(?:buy|purchase|send)\b.{0,80}\b(?:gift[ -]?cards?)\b/i', $fullText) === 1;
        $hasPaymentRequest = preg_match('/\b(?:change|update|new)\b.{0,50}\b(?:bank details|payment instructions|wire instructions|remittance details|direct deposit|payroll)\b|\b(?:wire transfer|transfer funds|fund transfer|pay(?:ment)?|invoice)\b.{0,80}\b(?:today|immediately|urgent|process|approve|details|instructions)\b/i', $fullText) === 1;
        $hasCredentialRequest = preg_match('/\b(?:password|login details|credentials?|mfa code|verification code|one[- ]time code|account verification)\b.{0,80}\b(?:send|share|provide|enter|reply|verify)\b|\b(?:send|share|provide|enter|reply)\b.{0,80}\b(?:password|login details|credentials?|mfa code|verification code|one[- ]time code)\b/i', $fullText) === 1;
        $hasCryptoRequest = preg_match('/\b(?:crypto(?:currency)?|bitcoin|wallet)\b.{0,80}\b(?:send|transfer|pay|deposit)\b|\b(?:send|transfer|pay|deposit)\b.{0,80}\b(?:crypto(?:currency)?|bitcoin|wallet)\b/i', $fullText) === 1;
        $hasSecrecyRequest = str_contains($fullText, 'do not contact')
            || str_contains($fullText, "don't contact")
            || preg_match('/\b(?:keep (?:this )?(?:confidential|secret)|bypass (?:the )?(?:normal )?(?:approval|process)|without (?:normal )?approval)\b/i', $fullText) === 1;
        $hasUrgency = preg_match('/\b(?:urgent|immediately|asap|today)\b/i', $fullText) === 1;

        $this->addHeuristicSignal($heuristicFlags, $heuristicSignals, $hasGiftCardRequest, 'bec_action_request', 'Gift-card action request detected.');
        $this->addHeuristicSignal($heuristicFlags, $heuristicSignals, $hasPaymentRequest, 'payment_request', 'Payment or bank-detail action request detected.');
        $this->addHeuristicSignal($heuristicFlags, $heuristicSignals, $hasCredentialRequest, 'credential_request', 'Credential or MFA-code request detected.');
        $this->addHeuristicSignal($heuristicFlags, $heuristicSignals, $hasCryptoRequest, 'bec_action_request', 'Cryptocurrency or wallet-transfer request detected.');
        $this->addHeuristicSignal(
            $heuristicFlags,
            $heuristicSignals,
            $hasSecrecyRequest && ($hasPaymentRequest || $hasCredentialRequest || $hasGiftCardRequest || $hasCryptoRequest || $hasUrgency),
            'bec_action_request',
            'Secrecy or approval-bypass request paired with a sensitive action detected.'
        );
        $this->addHeuristicSignal(
            $heuristicFlags,
            $heuristicSignals,
            $hasUrgency && ($hasPaymentRequest || $hasCredentialRequest || $hasGiftCardRequest || $hasCryptoRequest),
            'bec_action_request',
            'Urgent sensitive action request detected.'
        );
    }

    /**
     * @param array<int, string> $heuristicFlags
     * @param array<int, string> $heuristicSignals
     */
    private function addHeuristicSignal(array &$heuristicFlags, array &$heuristicSignals, bool $matches, string $signal, string $flag): void
    {
        if (! $matches) {
            return;
        }

        $heuristicFlags[] = $flag;
        $heuristicSignals[] = $signal;
    }

    /**
     * @param array<int, string> $heuristicSignals
     * @param array<int, string> $extractedUrls
     * @return array<int, string>
     */
    private function geminiEscalationReasons(
        ?string $deterministicOverride,
        array $heuristicSignals,
        array $extractedUrls,
        VirusTotalScanResult $virusTotalResult
    ): array {
        $reasons = $heuristicSignals;

        if ($deterministicOverride !== null && empty($reasons)) {
            $reasons[] = $deterministicOverride;
        }

        if (empty($extractedUrls)) {
            return $reasons;
        }

        if ($virusTotalResult->vendorFlagCount() > 0) {
            $reasons[] = 'url_vendor_flags';
        }

        if (count($extractedUrls) > 1) {
            $reasons[] = 'multiple_urls_not_fully_verified';
        }

        if (in_array($virusTotalResult->status, ['unknown', 'unavailable', 'rate_limited', 'failed'], true)) {
            $reasons[] = 'url_reputation_inconclusive';
        }

        if (! in_array('url_vendor_flags', $reasons, true)
            && ! in_array('multiple_urls_not_fully_verified', $reasons, true)
            && ! in_array('url_reputation_inconclusive', $reasons, true)) {
            $reasons[] = 'url_present';
        }

        return array_values(array_unique($reasons));
    }

    /**
     * @param array{matched: bool, accepted: bool, authentication: string, reason: string} $whitelistTrust
     * @return array<int, string>
     */
    private function initialDecisionTrace(?string $senderDomain, array $whitelistTrust): array
    {
        return [
            $senderDomain === null
                ? 'decision:sender_domain=malformed'
                : 'decision:sender_domain=normalized',
            'decision:layer_1.whitelist_match=' . ($whitelistTrust['matched'] ? 'yes' : 'no'),
            'decision:sender_authentication=' . $whitelistTrust['authentication'],
            'decision:whitelist_benefit=' . $whitelistTrust['reason'],
        ];
    }

    /**
     * @param array<string, mixed> $analysis
     * @param array<int, string> $decisionTrace
     * @return array<string, mixed>
     */
    private function withDecisionTrace(array $analysis, array $decisionTrace): array
    {
        $analysis['analysis_chain'] = array_values(array_unique(array_merge(
            $decisionTrace,
            $analysis['analysis_chain'] ?? []
        )));

        return $analysis;
    }

    private function buildAnalysisResult(
        string $detectionLayer,
        int $riskScore,
        string $verdict,
        string $threatCategory,
        array $analysisChain,
        string $finalReasoning,
        ?string $severity = null,
        ?bool $isThreat = null
    ): array {
        $riskScore = max(0, min(100, $riskScore));
        $normalizedVerdict = strtoupper(trim($verdict));

        if (!in_array($normalizedVerdict, ['SAFE', 'SUSPICIOUS', 'MALICIOUS'], true)) {
            throw new \InvalidArgumentException('Trusted analysis results must use a supported verdict.');
        }

        $normalizedThreatCategory = trim($threatCategory) !== '' ? trim($threatCategory) : 'None';
        $normalizedFinalReasoning = trim($finalReasoning) !== '' ? trim($finalReasoning) : 'No reasoning provided.';
        $normalizedAnalysisChain = array_values(array_filter(array_map(function ($step) {
            return trim((string) $step);
        }, $analysisChain)));

        if (empty($normalizedAnalysisChain)) {
            $normalizedAnalysisChain = [
                'Step 1: Evaluate sender identity and domain.',
                'Step 2: Evaluate financial or psychological intent.',
                'Step 3: Contextualize VirusTotal metadata.',
            ];
        }

        $normalizedIsThreat = $isThreat ?? ($normalizedVerdict !== 'SAFE' || $riskScore > 30);
        $normalizedSeverity = $severity ?? $this->determineSeverity($riskScore, $normalizedVerdict, $normalizedIsThreat);

        return [
            'is_threat' => $normalizedIsThreat,
            'detection_layer' => $detectionLayer,
            'severity' => $normalizedSeverity,
            'risk_score' => $riskScore,
            'reason' => $normalizedFinalReasoning,
            'verdict' => $normalizedVerdict,
            'threat_category' => $normalizedThreatCategory,
            'analysis_chain' => $normalizedAnalysisChain,
            'final_reasoning' => $normalizedFinalReasoning,
        ];
    }

    private function determineSeverity(int $riskScore, string $verdict, bool $isThreat): string
    {
        if (!$isThreat && $riskScore === 0) {
            return 'clean';
        }

        if ($verdict === 'MALICIOUS' || $riskScore >= 75) {
            return 'high';
        }

        if ($verdict === 'SUSPICIOUS' || $riskScore >= 40) {
            return 'medium';
        }

        return $riskScore > 0 ? 'low' : 'clean';
    }

    private function extractUrls(string $text): array
    {
        preg_match_all(
            '#\bhttps?://[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/))#',
            mb_substr($text, 0, self::MAX_URL_SCAN_TEXT_CHARS),
            $matches
        );

        return array_slice(array_values(array_unique($matches[0] ?? [])), 0, self::MAX_EXTRACTED_URLS);
    }

    private function buildExtractedUrls(string $text, array $extractedLinks): array
    {
        $urls = $this->extractUrls($text);

        foreach ($extractedLinks as $link) {
            if (!is_array($link)) {
                continue;
            }

            foreach (['resolved_url', 'url'] as $field) {
                $url = trim((string) ($link[$field] ?? ''));

                if ($url !== '') {
                    $urls[] = $url;
                }
            }
        }

        return array_slice(array_values(array_unique($urls)), 0, self::MAX_EXTRACTED_URLS);
    }

    private function normalizeExtractedLinks(mixed $links): array
    {
        if (!is_array($links)) {
            return [];
        }

        $normalizedLinks = [];

        foreach ($links as $link) {
            if (!is_array($link) || empty($link['url'])) {
                continue;
            }

            $normalizedLinks[] = [
                'url' => mb_substr((string) $link['url'], 0, 2048),
                'anchor_text' => isset($link['anchor_text']) && $link['anchor_text'] !== null
                    ? mb_substr((string) $link['anchor_text'], 0, 255)
                    : null,
                'domain' => isset($link['domain']) ? mb_substr((string) $link['domain'], 0, 255) : null,
                'resolved_url' => isset($link['resolved_url']) ? mb_substr((string) $link['resolved_url'], 0, 2048) : null,
                'resolved_domain' => isset($link['resolved_domain']) ? mb_substr((string) $link['resolved_domain'], 0, 255) : null,
                'has_text_mismatch' => (bool) ($link['has_text_mismatch'] ?? false),
                'has_suspicious_mismatch' => (bool) ($link['has_suspicious_mismatch'] ?? false),
            ];

            if (count($normalizedLinks) >= self::MAX_EXTRACTED_LINKS) {
                break;
            }
        }

        return $normalizedLinks;
    }

    private function extractSenderEmail(string $sender): string
    {
        if (preg_match('/<([^>]+)>/', $sender, $matches)) {
            return strtolower(trim($matches[1]));
        }

        if (preg_match('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $sender, $matches)) {
            return strtolower(trim($matches[0]));
        }

        return trim($sender);
    }

    private function jsonPromptValue(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) ?: 'null';
    }

    private function normalizeNullableString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        $normalized = trim((string) $value);

        return $normalized === '' || strtolower($normalized) === 'null' ? null : $normalized;
    }

    private function isMockMode(): bool
    {
        return strtolower((string) config('services.gemini.mode', 'live')) === 'mock';
    }
}
