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
            if (ScannedEmail::where('google_message_id', $email['id'])->exists()) {
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
            You are a cynical Tier-3 SOC Analyst. Analyze this email for phishing/impersonation.

            METADATA:
            - Subject: '$safeSubject'
            - Sender: '$safeSender'
            - Snippet: '$safeSnippet'

            CRITICAL SCORING RULES (0-100%):
            1. **IMPERSONATION (100% RISK):** Subject mentions Big Brand (Netflix, Google, Bank) BUT Sender is Public Domain (@gmail) or Mismatch.
            2. **URGENCY (80-90% RISK):** 'Verify', 'Suspended', 'Payment Declined'.
            3. **CLEAN (0%):** Known social/newsletter domains or personal chats.

            IMPORTANT HERE: Only set is_threat is true if risk_score is more than 30.

            OUTPUT FORMAT (JSON ONLY):
            {
                'is_threat': boolean,
                'severity': 'clean', 'low', 'medium', or 'high',
                'risk_score': integer (0-100),
                'reason': 'Mandatory 1 sentence explanation.'
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
