<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth; // 🟢 Import Auth
use App\Models\ScannedSms;           // 🟢 Import the Model
use Inertia\Inertia;

class SmsController extends Controller
{
    public function index()
    {
        return Inertia::render('SmsScanner');
    }

    public function analyze(Request $request)
    {
        $request->validate([
            'message' => 'required|string|max:1000',
        ]);

        $message = $request->input('message');
        $apiKey = env('GEMINI_API_KEY');

        if (empty($apiKey)) {
            return response()->json(['error' => 'Server Error: GEMINI_API_KEY is missing in .env file.'], 500);
        }

        $prompt = "You are a cybersecurity expert specializing in Smishing (SMS Phishing).
        Analyze the following text message: \"{$message}\"
        Return a strict JSON response (no markdown) with these keys:
        - is_threat (boolean)
        - risk_score (0-100)
        - severity (low, medium, high, critical)
        - type (string)
        - explanation (string)";

        try {
            $response = Http::withHeaders(['Content-Type' => 'application/json'])
                ->post("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={$apiKey}", [
                    'contents' => [['parts' => [['text' => $prompt]]]]
                ]);

            if ($response->failed()) {
                \Log::error('Gemini API Error: ' . $response->body());
                return response()->json(['error' => 'Google AI Error. Check logs for details.'], 500);
            }

            $jsonResponse = $response->json();

            if (!isset($jsonResponse['candidates'][0]['content']['parts'][0]['text'])) {
                \Log::error('Unexpected Gemini Response: ' . json_encode($jsonResponse));
                return response()->json(['error' => 'AI returned an empty or unexpected response.'], 500);
            }

            $rawText = $jsonResponse['candidates'][0]['content']['parts'][0]['text'];
            $cleanJson = str_replace(['```json', '```'], '', $rawText);

            // Decode the JSON
            $analysis = json_decode($cleanJson, true);

            // 🟢 NEW: SAVE TO DATABASE STARTS HERE
            ScannedSms::create([
                'user_id' => Auth::id(),
                'content' => $message,
                'is_threat' => $analysis['is_threat'] ?? false,
                'risk_score' => $analysis['risk_score'] ?? 0,
                'type' => $analysis['type'] ?? 'Unknown',
                'explanation' => $analysis['explanation'] ?? 'No explanation provided.',
            ]);
            // 🟢 END NEW CODE

            return response()->json($analysis);

        } catch (\Exception $e) {
            \Log::error('SMS Controller Crash: ' . $e->getMessage());
            return response()->json(['error' => 'Server Error: ' . $e->getMessage()], 500);
        }
    }
}
