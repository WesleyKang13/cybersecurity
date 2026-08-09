<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\MonitoredDomain;
use App\Models\WebSecurityScan;
use App\Notifications\SecurityAlertNotification;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class UniversalSecurityScannerService
{
    private const TIMEOUT_SECONDS = 5;

    public function __construct(
        private readonly SecurityAlertDispatcher $securityAlertDispatcher
    ) {
    }

    /**
     * @var list<string>
     */
    private const CRITICAL_HEADERS = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
    ];

    /**
     * @return array{
     *     scan: \App\Models\WebSecurityScan,
     *     issue_count: int
     * }
     */
    public function scan(MonitoredDomain $monitoredDomain): array
    {
        $domain = strtolower(trim($monitoredDomain->domain));
        $requestAudit = $this->performHttpAudit($domain);
        $sslAudit = $this->performSslAudit($domain);

        $missingHeaders = $this->resolveMissingHeaders($requestAudit['response']);
        $issues = $this->buildIssues(
            requestAudit: $requestAudit,
            sslAudit: $sslAudit,
            missingHeaders: $missingHeaders
        );
        $securityScore = $this->calculateSecurityScore(
            requestAudit: $requestAudit,
            sslAudit: $sslAudit,
            missingHeaders: $missingHeaders
        );

        $scan = $monitoredDomain->webSecurityScans()->create([
            'http_status' => $requestAudit['http_status'],
            'response_time_ms' => $requestAudit['response_time_ms'],
            'ssl_valid' => $sslAudit['ssl_valid'],
            'ssl_expires_at' => $sslAudit['ssl_expires_at'],
            'ssl_issuer' => $sslAudit['ssl_issuer'],
            'missing_headers' => $missingHeaders,
            'security_score' => $securityScore,
            'detected_issues' => $issues,
        ]);

        $monitoredDomain->forceFill([
            'ssl_certificate_info' => [
                'ssl_valid' => $sslAudit['ssl_valid'],
                'ssl_expires_at' => $sslAudit['ssl_expires_at']?->toIso8601String(),
                'ssl_issuer' => $sslAudit['ssl_issuer'],
                'http_status' => $requestAudit['http_status'],
                'response_time_ms' => $requestAudit['response_time_ms'],
            ],
        ])->save();

        $this->dispatchSslWarningAlert($monitoredDomain, $sslAudit);

        return [
            'scan' => $scan,
            'issue_count' => count($issues),
        ];
    }

    /**
     * @return array{
     *     response: \Illuminate\Http\Client\Response|null,
     *     http_status: int|null,
     *     response_time_ms: int|null,
     *     final_url: string,
     *     failure_reason: string|null
     * }
     */
    private function performHttpAudit(string $domain): array
    {
        $failureReason = null;

        foreach (["https://{$domain}", "http://{$domain}"] as $url) {
            $startedAt = microtime(true);

            try {
                $response = Http::withoutVerifying()
                    ->timeout(self::TIMEOUT_SECONDS)
                    ->connectTimeout(self::TIMEOUT_SECONDS)
                    ->accept('*/*')
                    ->get($url);

                return [
                    'response' => $response,
                    'http_status' => $response->status(),
                    'response_time_ms' => (int) round((microtime(true) - $startedAt) * 1000),
                    'final_url' => $url,
                    'failure_reason' => null,
                ];
            } catch (ConnectionException $e) {
                $failureReason = $e->getMessage();
                Log::notice("Web audit request failed for {$url}: {$e->getMessage()}");
            } catch (Throwable $e) {
                $failureReason = $e->getMessage();
                Log::warning("Web audit request error for {$url}: {$e->getMessage()}");
            }
        }

        return [
            'response' => null,
            'http_status' => null,
            'response_time_ms' => self::TIMEOUT_SECONDS * 1000,
            'final_url' => "https://{$domain}",
            'failure_reason' => $failureReason,
        ];
    }

    /**
     * @return array{
     *     ssl_valid: bool,
     *     ssl_expires_at: \Carbon\CarbonImmutable|null,
     *     ssl_issuer: string|null,
     *     error: string|null
     * }
     */
    private function performSslAudit(string $domain): array
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
            'socket' => [
                'connect_timeout' => self::TIMEOUT_SECONDS,
            ],
        ]);

        set_error_handler(static function (): bool {
            return true;
        });

        try {
            $client = stream_socket_client(
                "ssl://{$domain}:443",
                $errorNumber,
                $errorMessage,
                self::TIMEOUT_SECONDS,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if ($client === false) {
                return [
                    'ssl_valid' => false,
                    'ssl_expires_at' => null,
                    'ssl_issuer' => null,
                    'error' => $errorMessage !== '' ? $errorMessage : 'Unable to establish an SSL/TLS connection.',
                ];
            }

            stream_set_timeout($client, self::TIMEOUT_SECONDS);
            $parameters = stream_context_get_params($client);
            fclose($client);

            $certificate = $parameters['options']['ssl']['peer_certificate'] ?? null;
            if ($certificate === null) {
                return [
                    'ssl_valid' => false,
                    'ssl_expires_at' => null,
                    'ssl_issuer' => null,
                    'error' => 'No peer certificate was presented by the remote server.',
                ];
            }

            $certificateData = openssl_x509_parse($certificate);
            if ($certificateData === false) {
                return [
                    'ssl_valid' => false,
                    'ssl_expires_at' => null,
                    'ssl_issuer' => null,
                    'error' => 'Unable to parse the remote SSL/TLS certificate.',
                ];
            }

            $validTo = isset($certificateData['validTo_time_t'])
                ? CarbonImmutable::createFromTimestampUTC((int) $certificateData['validTo_time_t'])
                : null;
            $validFrom = isset($certificateData['validFrom_time_t'])
                ? CarbonImmutable::createFromTimestampUTC((int) $certificateData['validFrom_time_t'])
                : null;
            $now = CarbonImmutable::now('UTC');
            $isValid = $validTo !== null
                && $validTo->greaterThan($now)
                && ($validFrom === null || $validFrom->lessThanOrEqualTo($now));

            $issuer = $this->extractIssuerName($certificateData['issuer'] ?? []);

            return [
                'ssl_valid' => $isValid,
                'ssl_expires_at' => $validTo,
                'ssl_issuer' => $issuer,
                'error' => null,
            ];
        } finally {
            restore_error_handler();
        }
    }

    /**
     * @param array<mixed> $issuer
     */
    private function extractIssuerName(array $issuer): ?string
    {
        foreach (['O', 'CN', 'OU'] as $key) {
            if (!empty($issuer[$key]) && is_string($issuer[$key])) {
                return $issuer[$key];
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function resolveMissingHeaders(?Response $response): array
    {
        if ($response === null) {
            return self::CRITICAL_HEADERS;
        }

        $missingHeaders = [];

        foreach (self::CRITICAL_HEADERS as $headerName) {
            if ($response->header($headerName) === null) {
                $missingHeaders[] = $headerName;
            }
        }

        return $missingHeaders;
    }

    /**
     * @param array{
     *     response: \Illuminate\Http\Client\Response|null,
     *     http_status: int|null,
     *     response_time_ms: int|null,
     *     final_url: string,
     *     failure_reason: string|null
     * } $requestAudit
     * @param array{
     *     ssl_valid: bool,
     *     ssl_expires_at: \Carbon\CarbonImmutable|null,
     *     ssl_issuer: string|null,
     *     error: string|null
     * } $sslAudit
     * @param list<string> $missingHeaders
     * @return list<string>
     */
    private function buildIssues(array $requestAudit, array $sslAudit, array $missingHeaders): array
    {
        $issues = [];

        if ($requestAudit['http_status'] === null) {
            $issues[] = $requestAudit['failure_reason'] !== null
                ? "The website did not respond within 5 seconds: {$requestAudit['failure_reason']}"
                : 'The website did not respond within 5 seconds.';
        } elseif ($requestAudit['http_status'] >= 500) {
            $issues[] = "The website returned HTTP {$requestAudit['http_status']}, indicating a potential outage or load issue.";
        } elseif ($requestAudit['http_status'] >= 400) {
            $issues[] = "The website returned HTTP {$requestAudit['http_status']}, indicating the page is not serving normally.";
        }

        if (($requestAudit['response_time_ms'] ?? 0) > 5000) {
            $issues[] = 'The website exceeded the 5 second response-time threshold.';
        }

        foreach ($missingHeaders as $headerName) {
            $issues[] = "{$headerName} is missing from the HTTP response.";
        }

        if ($sslAudit['error'] !== null) {
            $issues[] = "SSL/TLS validation could not be completed: {$sslAudit['error']}";
        } elseif (!$sslAudit['ssl_valid']) {
            $issues[] = 'The SSL/TLS certificate is invalid or expired.';
        }

        if ($sslAudit['ssl_expires_at'] !== null) {
            $daysUntilExpiry = CarbonImmutable::now('UTC')->diffInDays($sslAudit['ssl_expires_at'], false);

            if ($daysUntilExpiry < 0) {
                $issues[] = 'The SSL/TLS certificate has expired.';
            } elseif ($daysUntilExpiry <= 30) {
                $issues[] = "The SSL/TLS certificate expires in {$daysUntilExpiry} day(s).";
            }
        }

        return array_values(array_unique($issues));
    }

    /**
     * @param array{
     *     response: \Illuminate\Http\Client\Response|null,
     *     http_status: int|null,
     *     response_time_ms: int|null,
     *     final_url: string,
     *     failure_reason: string|null
     * } $requestAudit
     * @param array{
     *     ssl_valid: bool,
     *     ssl_expires_at: \Carbon\CarbonImmutable|null,
     *     ssl_issuer: string|null,
     *     error: string|null
     * } $sslAudit
     * @param list<string> $missingHeaders
     */
    private function calculateSecurityScore(array $requestAudit, array $sslAudit, array $missingHeaders): int
    {
        $score = 100;

        $score -= count($missingHeaders) * 10;

        if ($requestAudit['http_status'] === null) {
            $score -= 35;
        } elseif ($requestAudit['http_status'] >= 500) {
            $score -= 30;
        } elseif ($requestAudit['http_status'] >= 400) {
            $score -= 15;
        }

        if (($requestAudit['response_time_ms'] ?? 0) > 5000) {
            $score -= 15;
        } elseif (($requestAudit['response_time_ms'] ?? 0) > 2500) {
            $score -= 10;
        }

        if ($sslAudit['error'] !== null || !$sslAudit['ssl_valid']) {
            $score -= 25;
        }

        if ($sslAudit['ssl_expires_at'] !== null) {
            $daysUntilExpiry = CarbonImmutable::now('UTC')->diffInDays($sslAudit['ssl_expires_at'], false);

            if ($daysUntilExpiry < 0) {
                $score -= 20;
            } elseif ($daysUntilExpiry <= 30) {
                $score -= 10;
            }
        }

        return max(0, min(100, $score));
    }

    /**
     * @param array{
     *     ssl_valid: bool,
     *     ssl_expires_at: \Carbon\CarbonImmutable|null,
     *     ssl_issuer: string|null,
     *     error: string|null
     * } $sslAudit
     */
    private function dispatchSslWarningAlert(MonitoredDomain $monitoredDomain, array $sslAudit): void
    {
        $expiresAt = $sslAudit['ssl_expires_at'] ?? null;

        if (!$expiresAt instanceof CarbonImmutable) {
            return;
        }

        $daysUntilExpiry = CarbonImmutable::now('UTC')->diffInDays($expiresAt, false);

        if ($daysUntilExpiry > 14) {
            return;
        }

        $cacheKey = "alert_ssl_{$monitoredDomain->id}";
        $status = Cache::remember($cacheKey, 86400, static fn (): string => 'ready');

        if ($status !== 'ready') {
            return;
        }

        Cache::put($cacheKey, 'sent', 86400);

        $severity = $daysUntilExpiry < 0
            ? 'CRITICAL'
            : ($daysUntilExpiry <= 7 ? 'HIGH' : 'WARNING');

        $message = $daysUntilExpiry < 0
            ? 'The SSL/TLS certificate has already expired.'
            : "The SSL/TLS certificate expires in {$daysUntilExpiry} day(s).";

        $this->securityAlertDispatcher->dispatch(
            new SecurityAlertNotification(
                alertType: 'ssl_warning',
                domainName: $monitoredDomain->domain,
                severity: $severity,
                message: "{$message} Issuer: " . ($sslAudit['ssl_issuer'] ?? 'Unknown') . '.'
            )
        );
    }
}
