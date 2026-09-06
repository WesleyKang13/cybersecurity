<?php

namespace App\Services;

use App\Models\ScannedUrl;
use App\Support\VirusTotalScanResult;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class VirusTotalService
{
    /**
     * Inspects only the first URL. This intentional quota guard is never used
     * to auto-clear an email that contains one or more URLs.
     *
     * @param  array<int, string>  $urls
     */
    public function inspectFirstUrl(array $urls): VirusTotalScanResult
    {
        if (empty($urls)) {
            return VirusTotalScanResult::skippedNoUrl();
        }

        $targetUrl = $urls[0];

        if (strtolower((string) config('services.gemini.mode', 'live')) === 'mock') {
            return VirusTotalScanResult::forStatus('unavailable', $targetUrl);
        }

        // We only scan the FIRST link to protect our 4 req/min rate limit.
        $cached = ScannedUrl::where('url', $targetUrl)->first();
        if ($cached) {
            Log::info("VirusTotal: Pulled {$targetUrl} from Database Cache.");

            return VirusTotalScanResult::cached($cached);
        }

        // VirusTotal v3 requires URLs to be Base64-URL encoded without the '=' padding.
        $urlIdentifier = rtrim(strtr(base64_encode($targetUrl), '+/', '-_'), '=');
        $apiKey = env('VIRUSTOTAL_API_KEY');

        if (empty($apiKey)) {
            return VirusTotalScanResult::forStatus('unavailable', $targetUrl);
        }

        try {
            $response = Http::withHeader('x-apikey', $apiKey)
                ->get("https://www.virustotal.com/api/v3/urls/{$urlIdentifier}");

            $this->throttleForRateLimit();

            if ($response->successful()) {
                $stats = $response->json('data.attributes.last_analysis_stats');
                $analysisResults = $response->json('data.attributes.last_analysis_results', []);

                // Tally up the security vendors that flagged this link
                $malicious = $stats['malicious'] ?? 0;
                $suspicious = $stats['suspicious'] ?? 0;
                $totalThreats = $malicious + $suspicious;
                $vendorFlags = [];

                foreach ($analysisResults as $vendorName => $result) {
                    if (in_array($result['category'] ?? null, ['malicious', 'suspicious'], true)) {
                        $vendorFlags[] = $vendorName;
                    }
                }

                // Save to our database cache forever
                $record = ScannedUrl::create([
                    'url' => $targetUrl,
                    'is_malicious' => $totalThreats > 0,
                    'malicious_votes' => $totalThreats,
                ]);

                $record->setAttribute('vendor_flags', $vendorFlags);

                return VirusTotalScanResult::apiChecked($record);
            }

            if ($response->status() === 404) {
                return VirusTotalScanResult::forStatus('unknown', $targetUrl);
            }

            if ($response->status() === 429) {
                return VirusTotalScanResult::forStatus('rate_limited', $targetUrl);
            }

            return VirusTotalScanResult::forStatus('unavailable', $targetUrl);

        } catch (\Exception $e) {
            Log::error('VirusTotal Error: '.$e->getMessage());

            return VirusTotalScanResult::forStatus('failed', $targetUrl);
        }
    }

    // 60 seconds / 4 requests: preserve the provider's queue-worker quota.
    protected function throttleForRateLimit(): void
    {
        sleep(15);
    }
}
