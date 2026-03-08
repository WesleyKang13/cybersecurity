<?php

namespace App\Services;

use App\Models\ScannedUrl;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class VirusTotalService
{
    public function scanFirstUrl($emailText)
    {
        // 1. REGEX: Rip out all http/https links from the email body
        preg_match_all('#\bhttps?://[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/))#', $emailText, $matches);
        $urls = array_unique($matches[0]);

        if (empty($urls)) {
            return null; // No links found, nothing to do
        }

        // We only scan the FIRST link to protect our 4 req/min rate limit
        $targetUrl = $urls[0];

        // 2. CACHE CHECK: Have we seen this exact link before?
        $cached = ScannedUrl::where('url', $targetUrl)->first();
        if ($cached) {
            Log::info("VirusTotal: Pulled {$targetUrl} from Database Cache.");
            return $cached;
        }

        // 3. VIRUSTOTAL API REQUEST
        // VirusTotal v3 requires URLs to be Base64-URL encoded without the '=' padding
        $urlIdentifier = rtrim(strtr(base64_encode($targetUrl), '+/', '-_'), '=');
        $apiKey = env('VIRUSTOTAL_API_KEY');

        try {
            // We ask VirusTotal if they have a report for this URL
            $response = Http::withHeader('x-apikey', $apiKey)
                ->get("https://www.virustotal.com/api/v3/urls/{$urlIdentifier}");

            // To protect the API limit, we force the queue worker to sleep for 15 seconds
            // after making a request (60 seconds / 4 requests = 15s per request)
            sleep(15);

            if ($response->successful()) {
                $stats = $response->json('data.attributes.last_analysis_stats');

                // Tally up the security vendors that flagged this link
                $malicious = $stats['malicious'] ?? 0;
                $suspicious = $stats['suspicious'] ?? 0;
                $totalThreats = $malicious + $suspicious;

                // Save to our database cache forever
                return ScannedUrl::create([
                    'url' => $targetUrl,
                    'is_malicious' => $totalThreats > 0,
                    'malicious_votes' => $totalThreats,
                ]);
            }

            return null; // URL hasn't been scanned by VT yet, or API failed

        } catch (\Exception $e) {
            Log::error("VirusTotal Error: " . $e->getMessage());
            return null;
        }
    }
}
