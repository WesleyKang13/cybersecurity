<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\ScannedEmail;
use App\Models\ScannedUrl;
use App\Models\User;
use App\Models\WhitelistedDomain;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class EmailScannerService
{
    private const MAX_PROMPT_BODY_CHARS = 6000;
    private const MAX_EXTRACTED_LINKS = 25;
    private const MAX_EXTRACTED_URLS = 50;
    private const MAX_URL_SCAN_TEXT_CHARS = 200000;
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const REQUEST_TIMEOUT_SECONDS = 10;

    public function __construct(protected VirusTotalService $virusTotalService)
    {
    }

    public function scanAndStore(User $user, array $email): array
    {
        $messageId = (string) ($email['google_message_id'] ?? '');
        $existing = ScannedEmail::withTrashed()
            ->where('google_message_id', $messageId)
            ->first();

        if ($existing) {
            return ['record' => $existing, 'created' => false];
        }

        $subject = trim((string) ($email['subject'] ?? 'No Subject'));
        $sender = trim((string) ($email['sender'] ?? 'Unknown'));
        $snippet = trim((string) ($email['snippet'] ?? ''));
        $body = trim((string) ($email['body'] ?? ''));
        $messageBody = $body !== '' ? $body : $snippet;
        $extractedLinks = $this->normalizeExtractedLinks($email['extracted_links'] ?? []);
        $pdfAttachments = array_values(array_filter($email['pdf_attachments'] ?? [], function ($attachment) {
            return is_array($attachment)
                && strtolower((string) ($attachment['mime_type'] ?? '')) === 'application/pdf'
                && !empty($attachment['base64_data']);
        }));
        $extractedUrls = $this->buildExtractedUrls(trim($snippet . ' ' . $messageBody), $extractedLinks);

        preg_match('/@([\w.-]+)/', $sender, $matches);
        $senderDomain = isset($matches[1]) ? strtolower(trim($matches[1], '>')) : '';

        $analysis = $this->runSecurityFunnel(
            subject: $subject,
            snippet: $snippet,
            messageBody: $messageBody,
            sender: $sender,
            senderDomain: $senderDomain,
            extractedUrls: $extractedUrls,
            extractedLinks: $extractedLinks,
            pdfAttachments: $pdfAttachments
        );

        $record = ScannedEmail::create([
            'user_id' => $user->id,
            'google_message_id' => $messageId,
            'subject' => $subject,
            'sender' => $sender,
            'snippet' => $snippet !== '' ? $snippet : $messageBody,
            'is_threat' => $analysis['is_threat'],
            'detection_layer' => $analysis['detection_layer'],
            'severity' => $analysis['severity'],
            'risk_score' => $analysis['risk_score'],
            'reason' => $analysis['reason'],
            'verdict' => $analysis['verdict'],
            'threat_category' => $analysis['threat_category'],
            'analysis_chain' => $analysis['analysis_chain'],
            'final_reasoning' => $analysis['final_reasoning'],
        ]);

        return ['record' => $record, 'created' => true];
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
            'created' => $created,
        ];
    }

    private function runSecurityFunnel(
        string $subject,
        string $snippet,
        string $messageBody,
        string $sender,
        string $senderDomain,
        array $extractedUrls,
        array $extractedLinks,
        array $pdfAttachments
    ): array {
        $whitelist = Cache::remember('trusted_domains', 3600, function () {
            return WhitelistedDomain::where('is_active', true)
                ->pluck('domain')
                ->toArray();
        });

        if (in_array($senderDomain, $whitelist, true)) {
            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 1 (Whitelist)',
                riskScore: 0,
                verdict: 'SAFE',
                threatCategory: 'None',
                analysisChain: [
                    "Sender domain '{$senderDomain}' matched the trusted whitelist.",
                    'No financial, secrecy, or procedure-bypass indicators required escalation.',
                    'VirusTotal context was not needed because the message was cleared at Layer 1.',
                ],
                finalReasoning: "The sender domain '{$senderDomain}' is on the trusted whitelist, so the message was auto-cleared before deeper technical analysis.",
                severity: 'clean',
                isThreat: false
            );
        }

        $subjectLower = strtolower($subject);
        $snippetLower = strtolower($snippet);
        $bodyLower = strtolower($messageBody);
        $fullText = trim($subjectLower . ' ' . $snippetLower . ' ' . $bodyLower);
        $heuristicFlags = [];

        $suspiciousTlds = ['.xyz', '.top', '.click', '.buzz', '.monster', '.cc', '.su', '.ru'];
        foreach ($suspiciousTlds as $tld) {
            if (str_ends_with($senderDomain, $tld)) {
                return $this->buildAnalysisResult(
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
                );
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

        if (in_array($senderDomain, $publicProviders, true)) {
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

        $vtInput = !empty($extractedUrls) ? implode(' ', $extractedUrls) : $fullText;
        $vtResult = $this->virusTotalService->scanFirstUrl($vtInput);
        $vtContext = $this->buildVirusTotalContext($vtResult, $extractedUrls);

        if ($vtResult && (int) $vtResult->malicious_votes >= 3) {
            return $this->buildAnalysisResult(
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
            );
        }

        $financialContext = $this->analyzeFinancialAttachments($pdfAttachments);
        $paymentRequestContext = array_values(array_filter($financialContext, function ($result) {
            return ($result['is_payment_request'] ?? false) === true;
        }));

        return $this->analyzeWithGemini(
            subject: $subject,
            sender: $sender,
            messageBody: $messageBody,
            extractedUrls: $extractedUrls,
            extractedLinks: $extractedLinks,
            vtContext: $vtContext,
            financialContext: $paymentRequestContext,
            heuristicFlags: $heuristicFlags
        );
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

            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 3 (AI Error)',
                riskScore: 0,
                verdict: 'SAFE',
                threatCategory: 'None',
                analysisChain: [
                    "Sender '{$this->extractSenderEmail($sender)}' reached Layer 3 for contextual analysis.",
                    'BEC and phishing intent analysis could not execute because the Gemini API key is missing.',
                    'VirusTotal and financial attachment metadata were preserved, but the final AI reasoning layer was unavailable.',
                ],
                finalReasoning: 'AI unavailable.',
                severity: 'clean',
                isThreat: false
            );
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
            $response = retry(3, function () use ($url, $prompt) {
                $res = Http::withHeaders(['Content-Type' => 'application/json'])
                    ->connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                    ->timeout(self::REQUEST_TIMEOUT_SECONDS)
                    ->post($url, [
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
                    ]);

                if ($res->failed()) {
                    throw new \RuntimeException("Gemini API Error: {$res->status()}");
                }

                return $res;
            }, 1000);

            $result = $this->parseGeminiResponse($response->json());

            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 3 (AI Analysis)',
                riskScore: (int) ($result['risk_score'] ?? 0),
                verdict: (string) ($result['verdict'] ?? 'SAFE'),
                threatCategory: (string) ($result['threat_category'] ?? 'None'),
                analysisChain: is_array($result['analysis_chain'] ?? null) ? $result['analysis_chain'] : [],
                finalReasoning: (string) ($result['final_reasoning'] ?? 'AI verification complete.')
            );
        } catch (\Throwable $e) {
            Log::error("Gemini Analysis Failed after retries: {$e->getMessage()}");

            return $this->buildAnalysisResult(
                detectionLayer: 'Layer 3 (AI Error)',
                riskScore: 0,
                verdict: 'SAFE',
                threatCategory: 'None',
                analysisChain: [
                    "Sender '{$senderEmail}' reached Layer 3 for contextual analysis.",
                    'BEC and phishing intent analysis failed because Gemini returned an invalid or unavailable response.',
                    'VirusTotal and financial attachment metadata could not be reconciled with AI reasoning, so the system defaulted to a non-blocking fallback.',
                ],
                finalReasoning: 'AI unavailable.',
                severity: 'clean',
                isThreat: false
            );
        }
    }

    private function analyzeFinancialAttachments(array $pdfAttachments): array
    {
        if (empty($pdfAttachments)) {
            return [];
        }

        return array_values(array_filter(array_map(function (array $attachment) {
            return $this->analyzeFinancialPdfAttachment($attachment);
        }, $pdfAttachments)));
    }

    private function analyzeFinancialPdfAttachment(array $attachment): ?array
    {
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
            return null;
        }

        try {
            $response = retry(3, function () use ($apiKey, $prompt, $attachment) {
                $res = Http::withHeaders(['Content-Type' => 'application/json'])
                    ->connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                    ->timeout(self::REQUEST_TIMEOUT_SECONDS)
                    ->post("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}", [
                        'contents' => [[
                            'parts' => [
                                ['text' => $prompt],
                                [
                                    'inlineData' => [
                                        'mimeType' => 'application/pdf',
                                        'data' => (string) $attachment['base64_data'],
                                    ],
                                ],
                            ],
                        ]],
                        'generationConfig' => [
                            'responseMimeType' => 'application/json',
                            'temperature' => 0.1,
                        ],
                    ]);

                if ($res->failed()) {
                    throw new \RuntimeException("Financial Gemini API Error: {$res->status()}");
                }

                return $res;
            }, 1000);

            $result = $this->parseGeminiResponse($response->json());

            return [
                'attachment_name' => $attachment['filename'] ?? null,
                'vendor_name' => $this->normalizeNullableString($result['vendor_name'] ?? null),
                'invoice_amount' => $this->normalizeNullableString($result['invoice_amount'] ?? null),
                'bank_routing_number' => $this->normalizeNullableString($result['bank_routing_number'] ?? null),
                'bank_account_number' => $this->normalizeNullableString($result['bank_account_number'] ?? null),
                'is_payment_request' => (bool) ($result['is_payment_request'] ?? false),
            ];
        } catch (\Throwable $e) {
            Log::error("Financial PDF Analysis Failed: {$e->getMessage()}");
            return null;
        }
    }

    private function parseGeminiResponse(array $payload): array
    {
        $textResponse = (string) ($payload['candidates'][0]['content']['parts'][0]['text'] ?? '');
        if (trim($textResponse) === '') {
            throw new \RuntimeException('Gemini returned an empty response.');
        }

        $sanitizedJson = $this->sanitizeJsonResponse($textResponse);
        $decoded = json_decode($sanitizedJson, true);

        if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Failed to decode Gemini JSON response: ' . json_last_error_msg());
        }

        return $decoded;
    }

    private function sanitizeJsonResponse(string $rawResponse): string
    {
        $cleaned = trim($rawResponse);
        $cleaned = preg_replace('/^```(?:json)?\s*/i', '', $cleaned) ?? $cleaned;
        $cleaned = preg_replace('/\s*```$/', '', $cleaned) ?? $cleaned;

        $firstBrace = strpos($cleaned, '{');
        $lastBrace = strrpos($cleaned, '}');

        if ($firstBrace !== false && $lastBrace !== false && $lastBrace >= $firstBrace) {
            $cleaned = substr($cleaned, $firstBrace, $lastBrace - $firstBrace + 1);
        }

        return trim($cleaned);
    }

    private function buildVirusTotalContext(?ScannedUrl $vtResult, array $extractedUrls): array
    {
        $vendorFlagCount = (int) ($vtResult->malicious_votes ?? 0);

        if ($vendorFlagCount >= 3) {
            $status = 'confirmed_technical_threat';
        } elseif ($vendorFlagCount >= 1) {
            $status = 'below_confirmation_threshold';
        } elseif (!empty($extractedUrls)) {
            $status = 'no_vendor_flags';
        } else {
            $status = 'no_urls_found';
        }

        return [
            'scanned_url' => $vtResult->url ?? ($extractedUrls[0] ?? null),
            'vendor_flag_count' => $vendorFlagCount,
            'vendor_flags' => array_values($vtResult->vendor_flags ?? []),
            'status' => $status,
            'note' => empty($extractedUrls)
                ? 'No URLs were extracted from the message.'
                : 'Only the first extracted URL was evaluated through VirusTotal to preserve API quota.',
        ];
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
            $normalizedVerdict = 'SAFE';
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
