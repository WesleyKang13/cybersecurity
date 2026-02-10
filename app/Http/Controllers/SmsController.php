<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use App\Models\ScannedSms;
use Inertia\Inertia;
use Illuminate\Support\Facades\Log;

class SmsController extends Controller
{
    public function index()
    {
        return Inertia::render('SmsScanner');
    }

    public function analyze(Request $request)
    {
        $request->validate([
            'sender'  => 'required|string|max:100',
            'message' => 'required|string|max:1000',
        ]);

        $sender = $request->input('sender');
        $message = $request->input('message');

        // Ensure this matches your config/services.php setup
        $apiKey = env('GEMINI_API_KEY');

        if (empty($apiKey)) {
            return response()->json(['error' => 'Server Error: GEMINI_API_KEY is missing.'], 500);
        }

        $prompt = "
            Role: Smishing Detection Expert.
            Analyze the following SMS for fraud.

            Sender: '$sender'
            Message: '$message'

            SCORING CRITERIA:
            - Identity Mismatch: Claims to be a bank/utility but comes from a standard 10-digit mobile number or suspicious shortcode.
            - Link Analysis: Flag any URL shorteners or non-official domains.
            - Tone: Look for 'Urgent Action Required,' 'Package Pending,' or 'Tax Refund.'
            - If the message is standard for which the organization will present then it is safe.

            is_threat = true ONLY if risk_score > 30.

            OUTPUT FORMAT (Strict JSON):
            {
            'is_threat': boolean,
            'risk_score': 0-100,
            'severity': 'low' | 'medium' | 'high' | 'critical',
            'type': 'Phishing' | 'Impersonation' | 'Spam' | 'Clean',
            'explanation': 'Clear, concise sentence.'
            }
        ";

        try {
            $response = retry(3, function () use ($apiKey, $prompt) {
                $res = Http::withHeaders(['Content-Type' => 'application/json'])
                    ->post("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}", [
                        'contents' => [['parts' => [['text' => $prompt]]]]
                    ]);

                if ($res->status() === 429 || $res->serverError()) {
                    throw new \Exception('API Rate Limit or Server Error');
                }

                return $res;
            }, 2000);

            if ($response->failed()) {
                Log::error('Gemini API Error: ' . $response->body());
                return response()->json(['error' => 'Google AI Error. Check logs.'], 500);
            }

            $jsonResponse = $response->json();

            if (!isset($jsonResponse['candidates'][0]['content']['parts'][0]['text'])) {
                return response()->json(['error' => 'AI returned an empty response.'], 500);
            }

            $rawText = $jsonResponse['candidates'][0]['content']['parts'][0]['text'];
            $cleanJson = str_replace(['```json', '```', 'json'], '', $rawText); // Clean markdown
            $analysis = json_decode($cleanJson, true);

            if (!$analysis) {
                 return response()->json(['error' => 'Failed to decode AI response.'], 500);
            }

            // Save to Database
            ScannedSms::create([
                'user_id'     => Auth::id(),
                'sender'      => $sender,
                'content'     => $message,
                'severity'    => $analysis['severity'] ?? 'low',
                'is_threat'   => $analysis['is_threat'] ?? false,
                'risk_score'  => $analysis['risk_score'] ?? 0,
                'type'        => $analysis['type'] ?? 'Unknown',
                'explanation' => $analysis['explanation'] ?? 'No explanation provided.',
            ]);

            return response()->json($analysis);

        } catch (\Exception $e) {
            Log::error('SMS Controller Crash: ' . $e->getMessage());
            return response()->json(['error' => 'System is busy. Please try again in a few seconds.'], 429);
        }
    }
}
