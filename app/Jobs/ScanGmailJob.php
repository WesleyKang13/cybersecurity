<?php

namespace App\Jobs;

use App\Models\User;
use App\Models\ScannedEmail;
use App\Services\GmailService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\Middleware\RateLimited;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ScanGmailJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $user;

    // 1. Tries: If the job fails (e.g., API is down), retry it 3 times max
    public $tries = 3;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    // 2. MIDDLEWARE: The "Traffic Control"
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

            ScannedEmail::create([
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
        }
    }

    private function runSecurityFunnel($subject, $snippet, $sender, $senderDomain)
    {
        // ---------------------------------------------------------
        // LAYER 1: THE WHITELIST (Known Good)
        // ---------------------------------------------------------
        $whitelist = [
            // --- Developer & Cloud Tools ---
            'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
            'koyeb.com', 'aws.amazon.com', 'digitalocean.com', 'cloudflare.com',
            'vercel.com', 'netlify.com', 'heroku.com', 'docker.com', 'npmjs.com',
            'sentry.io', 'datadoghq.com', 'postman.com',

            // --- Productivity & Work ---
            'slack.com', 'zoom.us', 'atlassian.com', 'trello.com', 'asana.com',
            'monday.com', 'notion.so', 'dropbox.com', 'box.com', 'docusign.com',
            'docusign.net', 'miro.com', 'figma.com', 'canva.com', 'calendly.com',
            'hubspot.com', 'salesforce.com', 'zendesk.com', 'intercom.com',

            // --- Social Media & Communication ---
            'linkedin.com', 'twitter.com', 'x.com', 'facebookmail.com',
            'instagram.com', 'pinterest.com', 'reddit.com', 'redditmail.com',
            'discord.com', 'tiktok.com', 'snapchat.com', 'twitch.tv', 'vimeo.com',

            // --- E-commerce & Delivery ---
            'amazon.com', 'amazon.co.uk', 'ebay.com', 'ebay.co.uk', 'etsy.com',
            'shopify.com', 'walmart.com', 'target.com', 'aliexpress.com',
            'uber.com', 'ubereats.com', 'deliveroo.co.uk', 'deliveroo.ie',
            'just-eat.ie', 'just-eat.co.uk', 'doordash.com', 'instacart.com',

            // --- Finance, Banking & Payments ---
            'paypal.com', 'stripe.com', 'squareup.com', 'revolut.com', 'monzo.com',
            'chase.com', 'bankofamerica.com', 'americanexpress.com', 'discover.com',
            'aib.ie', 'bankofireland.com', 'permanenttsb.ie', // Irish Banking

            // --- Entertainment & Gaming ---
            'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com',
            'steampowered.com', 'epicgames.com', 'ea.com', 'ubisoft.com',
            'playstation.com', 'xbox.com', 'nintendo.com', 'roblox.com',

            // --- Travel & Transport ---
            'airbnb.com', 'booking.com', 'expedia.com', 'skyscanner.net',
            'ryanair.com', 'aerlingus.com', 'aircoach.ie', 'britishairways.com',
            'delta.com', 'united.com', 'americanairlines.com', 'lyft.com',
            'irishrail.ie', 'dublinbus.ie',

            // --- Tech Giants (Corporate communications only, NOT their public webmail) ---
            'google.com', 'apple.com', 'microsoft.com', 'meta.com',

            // --- News, Education & Government ---
            'medium.com', 'quora.com', 'wikipedia.org', 'coursera.org', 'udemy.com',
            'nytimes.com', 'bbc.co.uk', 'bbc.com', 'theguardian.com', 'wsj.com',
            'revenue.ie', 'mygovid.ie', 'hse.ie', 'anpost.com'
        ];

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

        $publicProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com'];
        $urgentKeywords = ['urgent', 'suspend', 'immediate action', 'password reset', 'invoice', 'verify your account'];

        if (in_array($senderDomain, $publicProviders)) {
            foreach ($urgentKeywords as $keyword) {
                if (str_contains($subjectLower, $keyword) || str_contains($snippetLower, $keyword)) {
                    return [
                        'is_threat' => true,
                        'detection_layer' => 'Layer 2 (Heuristics)',
                        'severity' => 'high',
                        'risk_score' => 90,
                        'reason' => "Manual Rule: Public provider ({$senderDomain}) using suspicious keyword: '{$keyword}'."
                    ];
                }
            }
        }

        // ---------------------------------------------------------
        // LAYER 3: THE AI DETECTIVE (Fallback)
        // ---------------------------------------------------------
        return $this->analyzeWithGemini($subject, $snippet, $sender);
    }

    private function analyzeWithGemini($subject, $snippet, $sender)
    {
        $apiKey = env('GEMINI_API_KEY');;
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
            // Attempt 3 times. Wait 1s, then 2s, then 4s between tries.
            $response = retry(3, function () use ($url, $prompt) {

                // Added 'withHeaders' for JSON content type
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
            return ['is_threat' => false, 'severity' => 'clean', 'risk_score' => 0, 'reason' => 'AI unavailable'];
        }
    }
}
