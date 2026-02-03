<?php

namespace App\Jobs;

use App\Models\User;
use App\Models\ScannedEmail;
use App\Services\GmailService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ScanGmailJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $user;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function handle(): void
    {
        if (!$this->user->token) {
            return;
        }

        $gmail = new GmailService($this->user);
        $emails = $gmail->fetchLatestEmails(5);

        foreach ($emails as $email) {
            // Check if scanned before
            if (ScannedEmail::where('google_message_id', $email['id'])->exists()) {
                continue;
            }

            // RATE LIMITING: Pause for 4 seconds to respect Free Tier quota
            sleep(4);

            // Ask Gemini
            // Pass the sender ('from') so the AI can check it
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

    /**
     * Send the email content to Google Gemini for analysis
     */
   private function analyzeWithGemini($subject, $snippet, $sender)
    {
        $apiKey = config('services.gemini.key');
        $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}";

        // Sanitize inputs to prevent JSON breaking
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

            OUTPUT FORMAT (JSON ONLY):
            {
                'is_threat': boolean,
                'severity': 'clean', 'low', 'medium', or 'high',
                'risk_score': integer (0-100),
                'reason': 'Mandatory 1 sentence explanation.'
            }
        ";

        try {
            $response = Http::post($url, [
                'contents' => [['parts' => [['text' => $prompt]]]],
                // 👇 NEW: Disable Safety Filters so it reads the phishing text
                'safetySettings' => [
                    ['category' => 'HARM_CATEGORY_HARASSMENT', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_HATE_SPEECH', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold' => 'BLOCK_NONE'],
                    ['category' => 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold' => 'BLOCK_NONE'],
                ]
            ]);

            $json = $response->json();

            if (isset($json['error'])) {
                // Check storage/logs/laravel.log for the exact message!
                Log::error("Gemini API Error: " . $json['error']['message']);
                return ['is_threat' => false, 'severity' => 'clean', 'risk_score' => 0, 'reason' => 'API Error: ' . $json['error']['message']];
            }

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
            Log::error("Gemini Connection Error: " . $e->getMessage());
            return ['is_threat' => false, 'severity' => 'clean', 'risk_score' => 0, 'reason' => 'Connection Failed'];
        }
    }
}
