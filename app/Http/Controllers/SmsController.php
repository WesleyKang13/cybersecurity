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

        // 👇 FIXED: The full, strict prompt to ensure JSON keys match your Frontend
        $prompt = "
            You are a cybersecurity expert specializing in Smishing (SMS Phishing) detection.
            Analyze the following SMS context:

            Sender: \"{$sender}\"
            Message: \"{$message}\"

            CRITICAL SCORING RULES:
            - If the message claims to be from a known brand (Bank, Post, Netflix) but the Sender is a random number or unrelated shortcode, flag as HIGH THREAT (Mismatch).
            - Look for urgency cues ('verify', 'suspended', 'act now').
            - only set is_threat is true if the risk_score is more than 30

            OUTPUT FORMAT (Strict JSON, no markdown):
            {
                \"is_threat\": boolean,
                \"risk_score\": integer (0-100),
                \"severity\": \"low\", \"medium\", \"high\", or \"critical\",
                \"type\": \"string (e.g., 'Phishing', 'Impersonation', 'Clean')\",
                \"explanation\": \"string (A clear, short sentence explaining why.)\"
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
