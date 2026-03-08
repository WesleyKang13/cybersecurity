<?php

namespace App\Jobs;

use App\Models\User;
use App\Models\ScannedEmail;
use App\Models\WhitelistedDomain; // <-- ADDED
use App\Services\GmailService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\Middleware\RateLimited;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

class ScanGmailJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $user;

    // Tries: If the job fails (e.g., API is down), retry it 3 times max
    public $tries = 3;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    // MIDDLEWARE: The "Traffic Control"
    public function middleware()
    {
        return [new RateLimited('gemini-api')];
    }

    public function handle(): void
    {
        if (!$this->user->token) {
            return;
        }

        $gmail = new GmailService($this->user);

        // Fetch 5 emails to ensure we don't miss new ones
        $emails = $gmail->fetchLatestEmails(5);

        foreach ($emails as $email) {
            // Skip if already scanned
            if (ScannedEmail::withTrashed()->where('google_message_id', $email['id'])->exists()) {
                continue;
            }

            // EXTRACT THE SENDER DOMAIN (e.g., "support@github.com" -> "github.com")
            preg_match('/@([\w.-]+)/', $email['from'], $matches);
            $senderDomain = isset($matches[1]) ? strtolower(trim($matches[1], '>')) : '';

            // PASS TO THE SECURITY FUNNEL (Whitelist -> Rules -> AI)
            $analysis = $this->runSecurityFunnel($email['subject'], $email['snippet'], $email['from'], $senderDomain);

            $scannedEmail = ScannedEmail::create([
                'user_id' => $this->user->id,
                'google_message_id' => $email['id'],
                'subject' => $email['subject'],
                'sender' => $email['from'],
                'snippet' => $email['snippet'],
                'is_threat' => $analysis['is_threat'],
                'detection_layer' => $analysis['detection_layer'],
                'severity' => $analysis['severity'],
                'risk_score' => $analysis['risk_score'],
                'reason' => $analysis['reason'] ?? null,
            ]);

            // ---------------------------------------------------------
            // 🛡️ THE ACTIVE DEFENSE: AUTO-QUARANTINE
            // ---------------------------------------------------------
            // Check if the email is highly dangerous AND the user turned the feature ON
            if ($analysis['risk_score'] >= 90 && $this->user->auto_quarantine) {
                try {
                    // Extract the access token (Depends on how you cast the token column, usually string or array)
                    $accessToken = is_array($this->user->token) ? $this->user->token['access_token'] ?? $this->user->token : $this->user->token;

                    // Tell Google to yank it out of the Inbox and drop it in Spam
                    $response = Http::withToken($accessToken)
                        ->post("https://gmail.googleapis.com/gmail/v1/users/me/messages/{$email['id']}/modify", [
                            'addLabelIds' => ['SPAM'],
                            'removeLabelIds' => ['INBOX']
                        ]);

                    if ($response->successful()) {
                        Log::info("🛡️ Active Defense: Quarantined Email {$email['id']} for User {$this->user->id}");

                        // Optional: You could update the ScannedEmail to record that it was quarantined
                        $scannedEmail->update(['is_quarantined' => true]);
                        // $scannedEmail->update(['reason' => $scannedEmail->reason . ' [AUTO-QUARANTINED]']);
                    } else {
                        Log::error("Failed to auto-quarantine: " . $response->body());
                    }
                } catch (\Exception $e) {
                    Log::error("Auto-Quarantine Exception: " . $e->getMessage());
                }
            }

        }
    }

    private function runSecurityFunnel($subject, $snippet, $sender, $senderDomain)
    {
        // ---------------------------------------------------------
        // LAYER 1: THE DYNAMIC WHITELIST (Cached for 1 hour)
        // ---------------------------------------------------------
        $whitelist = Cache::remember('trusted_domains', 3600, function () {
            return WhitelistedDomain::where('is_active', true)
                ->pluck('domain')
                ->toArray();
        });

        if (in_array($senderDomain, $whitelist)) {
            return [
                'is_threat' => false,
                'detection_layer' => 'Layer 1 (Whitelist)',
                'severity' => 'clean',
                'risk_score' => 0,
                'reason' => "Auto-cleared: '{$senderDomain}' is a verified trusted domain."
            ];
        }

        // ---------------------------------------------------------
        // LAYER 2: MANUAL HEURISTICS (Known Bad)
        // ---------------------------------------------------------
        $subjectLower = strtolower($subject);
        $snippetLower = strtolower($snippet);
        // Combine them to make searching easier
        $fullText = $subjectLower . ' ' . $snippetLower;

        // RULE A: Highly Suspicious Top-Level Domains (TLDs)
        // Hackers buy these in bulk for $0.99 to send spam.
        $suspiciousTlds = ['.xyz', '.top', '.click', '.buzz', '.monster', '.cc', '.su', '.ru'];
        foreach ($suspiciousTlds as $tld) {
            if (str_ends_with($senderDomain, $tld)) {
                return [
                    'is_threat' => true,
                    'detection_layer' => 'Layer 2 (Heuristics)',
                    'severity' => 'high',
                    'risk_score' => 95,
                    'reason' => "Manual Rule: Sender domain uses a highly suspicious extension ('{$tld}')."
                ];
            }
        }

        // RULE B: Public Provider Abuse (Urgency & Impersonation)
        $publicProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'proton.me', 'mail.com'];

        if (in_array($senderDomain, $publicProviders)) {

            // 1. The Urgency Check
            $urgentKeywords = [
                'urgent', 'suspend', 'immediate action', 'password reset', 'invoice',
                'verify your account', 'unauthorized login', 'account limited', 'final notice', 'document attached'
            ];
            foreach ($urgentKeywords as $keyword) {
                if (str_contains($fullText, $keyword)) {
                    return [
                        'is_threat' => true,
                        'detection_layer' => 'Layer 2 (Heuristics)',
                        'severity' => 'high',
                        'risk_score' => 90,
                        'reason' => "Manual Rule: Public provider ({$senderDomain}) using suspicious urgency keyword: '{$keyword}'."
                    ];
                }
            }

            // 2. The Brand Impersonation Check (e.g., 'Apple Support' sent from a @gmail.com address)
            $impersonatedBrands = ['paypal', 'amazon', 'apple', 'microsoft', 'netflix', 'meta', 'facebook', 'bank', 'support'];
            foreach ($impersonatedBrands as $brand) {
                // We only check the subject here, as snippets often naturally mention brands
                if (str_contains($subjectLower, $brand)) {
                    return [
                        'is_threat' => true,
                        'detection_layer' => 'Layer 2 (Heuristics)',
                        'severity' => 'high',
                        'risk_score' => 95,
                        'reason' => "Manual Rule: Public provider ({$senderDomain}) attempting to impersonate brand: '{$brand}'."
                    ];
                }
            }
        }

        // RULE C: Known Scam & Extortion Phrases
        // If an email makes it here, it is NOT whitelisted. If it contains these phrases, kill it instantly.
        $scamPhrases = [
            'bitcoin giveaway', 'wallet validation', 'seed phrase', 'guaranteed return',
            'i have recorded you', 'webcam hacked', 'pay me in bitcoin', 'transfer funds immediately'
        ];

        foreach ($scamPhrases as $phrase) {
            if (str_contains($fullText, strtolower($phrase))) {
                return [
                    'is_threat' => true,
                    'detection_layer' => 'Layer 2 (Heuristics)',
                    'severity' => 'high',
                    'risk_score' => 99,
                    'reason' => "Manual Rule: Detected known scam or extortion phrase: '{$phrase}'."
                ];
            }
        }

        // ---------------------------------------------------------
        // LAYER 3: THE AI DETECTIVE (Fallback)
        // ---------------------------------------------------------
        return $this->analyzeWithGemini($subject, $snippet, $sender);
    }

    private function analyzeWithGemini($subject, $snippet, $sender)
    {
        $apiKey = env('GEMINI_API_KEY');
        $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}";

        $safeSubject = addslashes($subject);
        $safeSender = addslashes($sender);
        $safeSnippet = addslashes($snippet);

        $prompt = "
            Role: Cynical Tier-3 SOC Analyst.
            Task: Analyze email metadata for phishing.

            INPUT:
            - Subject: '$safeSubject'
            - Sender: '$safeSender'
            - Snippet: '$safeSnippet'

            SCORING LOGIC:
            1. Impersonation: Sender's display name or subject claims a 'Big Brand' identity, but the email domain is unrelated or a public provider (@gmail, @outlook)
                but please do check if it is legitimate.
            2. Social Engineering: Extreme urgency, threats of account closure, or suspicious 'Action Required' phrases.
            3. Link Discrepancy: Check snippet for URLs that don't match the claimed sender.
            4. False Positive Check: If it is a personal/informal conversation or a newsletter from a verified domain, score < 20.
            5. Always check for the email if it is legitimate first, especially big brands. If it is then its not a threat.
            6. If the sender is claiming itself from an agency or organization but email is not from that company then flag as high threat.

            is_threat = true ONLY if risk_score > 30.

            OUTPUT FORMAT (JSON ONLY, no prose):
            {
            'is_threat': boolean,
            'severity': 'clean' | 'low' | 'medium' | 'high',
            'risk_score': 0-100,
            'reason': '1 sentence specific to the data provided.'
            }
        ";

        try {
            // 3. RETRY LOGIC: Exponential Backoff
            $response = retry(3, function () use ($url, $prompt) {

                $res = Http::withHeaders(['Content-Type' => 'application/json'])
                    ->post($url, [
                        'contents' => [['parts' => [['text' => $prompt]]]],
                        'safetySettings' => [
                            ['category' => 'HARM_CATEGORY_HARASSMENT', 'threshold' => 'BLOCK_NONE'],
                            ['category' => 'HARM_CATEGORY_HATE_SPEECH', 'threshold' => 'BLOCK_NONE'],
                            ['category' => 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold' => 'BLOCK_NONE'],
                            ['category' => 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold' => 'BLOCK_NONE'],
                        ]
                    ]);

                // If we hit Rate Limit (429) or Server Error (5xx), throw exception to trigger retry
                if ($res->failed()) {
                     throw new \Exception("Gemini API Error: " . $res->status());
                }

                return $res;
            }, 1000); // 1000ms = 1 second base wait

            $json = $response->json();
            $textResponse = $json['candidates'][0]['content']['parts'][0]['text'] ?? '{}';
            $textResponse = str_replace(['```json', '```', 'json'], '', $textResponse);
            $result = json_decode($textResponse, true);

            return [
                'is_threat' => $result['is_threat'] ?? false,
                'detection_layer' => 'Layer 3 (AI Analysis)',
                'severity' => $result['severity'] ?? 'clean',
                'risk_score' => $result['risk_score'] ?? 0,
                'reason' => $result['reason'] ?? 'AI verification complete.',
            ];

        } catch (\Exception $e) {
            Log::error("Gemini Analysis Failed after retries: " . $e->getMessage());
            return [
                'is_threat' => false,
                'detection_layer' => 'Layer 3 (AI Error)',
                'severity' => 'clean',
                'risk_score' => 0,
                'reason' => 'AI unavailable'
            ];
        }
    }
}
