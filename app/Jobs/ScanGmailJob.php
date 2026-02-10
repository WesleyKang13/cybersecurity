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

            // Ask Gemini (with Retry Logic built-in)
            $analysis = $this->analyzeWithGemini($email['subject'], $email['snippet'], $email['from']);

            ScannedEmail::create([
                'user_id' => $this->user->id,
                'google_message_id' => $email['id'],
                'subject' => $email['subject'],
                'sender' => $email['from'],
                'snippet' => $email['snippet'],
                'is_threat' => $analysis['is_threat'],
                'severity' => $analysis['severity'],
                'risk_score' => $analysis['risk_score'],
                'reason' => $analysis['reason'] ?? null,
            ]);
        }
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
