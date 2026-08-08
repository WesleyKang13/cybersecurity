<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

class EmailOriginService
{
    private const LOOKUP_CACHE_TTL = 86400;
    private const CONNECT_TIMEOUT_SECONDS = 3;
    private const REQUEST_TIMEOUT_SECONDS = 5;

    private const TRUSTED_PROVIDERS = [
        [
            'name' => 'Google Workspace',
            'organization' => 'Google LLC',
            'asns' => ['AS15169'],
            'patterns' => ['google llc', 'google workspace', 'gmail', 'google'],
        ],
        [
            'name' => 'Microsoft 365',
            'organization' => 'Microsoft Corporation',
            'asns' => ['AS8075'],
            'patterns' => ['microsoft corporation', 'microsoft 365', 'office 365', 'outlook', 'exchange online'],
        ],
        [
            'name' => 'Yahoo Mail',
            'organization' => 'Yahoo',
            'asns' => ['AS36647'],
            'patterns' => ['yahoo', 'oath holdings', 'verizon media'],
        ],
        [
            'name' => 'Fastmail',
            'organization' => 'Fastmail Pty Ltd',
            'asns' => ['AS6412'],
            'patterns' => ['fastmail'],
        ],
        [
            'name' => 'Apple Mail',
            'organization' => 'Apple Inc.',
            'asns' => ['AS6185'],
            'patterns' => ['apple inc', 'icloud', 'me.com'],
        ],
    ];

    private const CLOUD_HOST_PATTERNS = [
        'amazon',
        'aws',
        'digitalocean',
        'hetzner',
        'linode',
        'vultr',
    ];

    public function trace(string $rawHeaders): array
    {
        $headers = $this->parseHeaders($rawHeaders);
        $receivedHeaders = [];
        $originCandidateHeaders = [];

        foreach ($headers as $header) {
            $normalizedName = strtolower($header['name']);

            if ($normalizedName === 'received') {
                $receivedHeaders[] = $header;
            }

            if (in_array($normalizedName, ['x-originating-ip', 'x-sender-ip', 'authentication-results'], true)) {
                $originCandidateHeaders[] = $header;
            }
        }

        $authentication = $this->extractAuthenticationState($headers);
        $hopsDetail = [];
        $seenIps = [];

        foreach ($originCandidateHeaders as $header) {
            $this->appendHeaderIps($hopsDetail, $seenIps, $header);
        }

        foreach (array_reverse($receivedHeaders) as $header) {
            $this->appendHeaderIps($hopsDetail, $seenIps, $header);
        }

        $originatingIp = $hopsDetail[0]['ip'] ?? null;
        $intelligence = $originatingIp ? $this->lookupIp($originatingIp) : [];
        $trustedProvider = $this->matchTrustedProvider($intelligence);
        $isTrustedProvider = $trustedProvider !== null
            && ($authentication['spf_pass'] === true || $authentication['dkim_pass'] === true);
        $isHostingProvider = $this->isCloudHostingProvider($intelligence);
        $isHostingProviderWarning = $isHostingProvider && $this->hasCloudHostWarning($authentication);
        $isProxyOrVpn = $this->isExplicitProxyOrVpn($intelligence);
        $originNote = null;

        if ($isTrustedProvider) {
            $isHostingProvider = false;
            $isHostingProviderWarning = false;
            $isProxyOrVpn = false;
            $originNote = sprintf(
                'Sent via official %s mail infrastructure (client IP hidden by provider for privacy).',
                $trustedProvider['name']
            );
        }

        return [
            'originating_ip' => $originatingIp,
            'location' => [
                'country' => $intelligence['country'] ?? null,
                'city' => $intelligence['city'] ?? null,
            ],
            'isp' => [
                'name' => $intelligence['isp'] ?? null,
                'asn' => $intelligence['as'] ?? null,
                'organization' => $intelligence['org'] ?? null,
            ],
            'provider_name' => $trustedProvider['name'] ?? null,
            'is_trusted_provider' => $isTrustedProvider,
            'origin_note' => $originNote,
            'authentication' => $authentication,
            'is_hosting_provider' => $isHostingProvider,
            'is_hosting_provider_warning' => $isHostingProviderWarning,
            'is_proxy_or_vpn' => $isProxyOrVpn,
            'hop_count' => count($hopsDetail),
            'hops_detail' => $hopsDetail,
        ];
    }

    /**
     * @return array<int, array{name: string, value: string, raw: string}>
     */
    private function parseHeaders(string $rawHeaders): array
    {
        $lines = preg_split("/\r\n|\n|\r/", $rawHeaders) ?: [];
        $unfoldedHeaders = [];
        $currentHeader = null;

        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }

            if (preg_match('/^\s+/', $line) === 1 && $currentHeader !== null) {
                $currentHeader .= ' ' . trim($line);
                continue;
            }

            if ($currentHeader !== null) {
                $unfoldedHeaders[] = $currentHeader;
            }

            $currentHeader = trim($line);
        }

        if ($currentHeader !== null) {
            $unfoldedHeaders[] = $currentHeader;
        }

        $headers = [];

        foreach ($unfoldedHeaders as $headerLine) {
            $separatorPosition = strpos($headerLine, ':');

            if ($separatorPosition === false) {
                continue;
            }

            $headers[] = [
                'name' => trim(substr($headerLine, 0, $separatorPosition)),
                'value' => trim(substr($headerLine, $separatorPosition + 1)),
                'raw' => $headerLine,
            ];
        }

        return $headers;
    }

    /**
     * @param array{name: string, value: string, raw: string} $header
     * @param array<string, bool> $seenIps
     * @param array<int, array{sequence: int, source_header: string, ip: string, raw_header: string}> $hopsDetail
     */
    private function appendHeaderIps(array &$hopsDetail, array &$seenIps, array $header): void
    {
        foreach ($this->extractPublicIps($header['value']) as $ip) {
            if (isset($seenIps[$ip])) {
                continue;
            }

            $seenIps[$ip] = true;
            $hopsDetail[] = [
                'sequence' => count($hopsDetail) + 1,
                'source_header' => $header['name'],
                'ip' => $ip,
                'raw_header' => $header['raw'],
            ];
        }
    }

    /**
     * @return array<int, string>
     */
    private function extractPublicIps(string $headerValue): array
    {
        preg_match_all('/[\[\(<"]?([A-Fa-f0-9:.]+)[\]\)>"]?/', $headerValue, $matches);

        $ips = [];

        foreach ($matches[1] ?? [] as $candidate) {
            $ip = trim($candidate, "[]()<>\"' ");

            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                continue;
            }

            $ips[] = $ip;
        }

        return array_values(array_unique($ips));
    }

    /**
     * @return array<string, mixed>
     */
    private function lookupIp(string $ip): array
    {
        $cacheKey = "ip_trace_{$ip}";
        $cached = Cache::get($cacheKey);

        if (is_array($cached)) {
            return $cached;
        }

        try {
            $response = Http::connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                ->timeout(self::REQUEST_TIMEOUT_SECONDS)
                ->acceptJson()
                ->get("http://ip-api.com/json/{$ip}", [
                    'fields' => 'status,message,country,city,isp,org,as,asname,proxy,hosting,query',
                ]);

            if (!$response->successful()) {
                return [];
            }

            $payload = $response->json();

            if (!is_array($payload) || ($payload['status'] ?? null) !== 'success') {
                return [];
            }

            Cache::put($cacheKey, $payload, self::LOOKUP_CACHE_TTL);

            return $payload;
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * @param array<int, array{name: string, value: string, raw: string}> $headers
     * @return array{spf_pass: ?bool, dkim_pass: ?bool, domain_alignment_pass: ?bool}
     */
    private function extractAuthenticationState(array $headers): array
    {
        $spfStatuses = [];
        $dkimStatuses = [];
        $dmarcStatuses = [];

        foreach ($headers as $header) {
            if (strtolower($header['name']) !== 'authentication-results') {
                continue;
            }

            $value = $header['value'];
            $spfStatus = $this->extractAuthenticationStatus($value, 'spf');
            $dkimStatus = $this->extractAuthenticationStatus($value, 'dkim');
            $dmarcStatus = $this->extractAuthenticationStatus($value, 'dmarc');

            if ($spfStatus !== null) {
                $spfStatuses[] = $spfStatus;
            }

            if ($dkimStatus !== null) {
                $dkimStatuses[] = $dkimStatus;
            }

            if ($dmarcStatus !== null) {
                $dmarcStatuses[] = $dmarcStatus;
            }
        }

        return [
            'spf_pass' => $this->normalizeAuthenticationDecision($spfStatuses),
            'dkim_pass' => $this->normalizeAuthenticationDecision($dkimStatuses),
            'domain_alignment_pass' => $this->normalizeAuthenticationDecision($dmarcStatuses),
        ];
    }

    private function extractAuthenticationStatus(string $value, string $mechanism): ?string
    {
        if (!preg_match('/\b' . preg_quote($mechanism, '/') . '=(pass|bestguesspass|fail|softfail|temperror|permerror|neutral|none)\b/i', $value, $matches)) {
            return null;
        }

        return strtolower($matches[1]);
    }

    /**
     * @param array<int, string> $statuses
     */
    private function normalizeAuthenticationDecision(array $statuses): ?bool
    {
        if (in_array('pass', $statuses, true) || in_array('bestguesspass', $statuses, true)) {
            return true;
        }

        foreach (['fail', 'softfail', 'temperror', 'permerror'] as $failureState) {
            if (in_array($failureState, $statuses, true)) {
                return false;
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $intelligence
     * @return array{name: string, organization: string, asns: array<int, string>, patterns: array<int, string>}|null
     */
    private function matchTrustedProvider(array $intelligence): ?array
    {
        $providerText = $this->buildProviderText($intelligence);
        $asn = strtoupper((string) ($intelligence['as'] ?? ''));

        foreach (self::TRUSTED_PROVIDERS as $provider) {
            if (in_array($asn, $provider['asns'], true)) {
                return $provider;
            }

            foreach ($provider['patterns'] as $pattern) {
                if ($providerText !== '' && str_contains($providerText, strtolower($pattern))) {
                    return $provider;
                }
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $intelligence
     */
    private function isCloudHostingProvider(array $intelligence): bool
    {
        if (($intelligence['hosting'] ?? false) !== true) {
            return false;
        }

        $providerText = $this->buildProviderText($intelligence);

        foreach (self::CLOUD_HOST_PATTERNS as $pattern) {
            if ($providerText !== '' && str_contains($providerText, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array{spf_pass: ?bool, dkim_pass: ?bool, domain_alignment_pass: ?bool} $authentication
     */
    private function hasCloudHostWarning(array $authentication): bool
    {
        return $authentication['spf_pass'] === false
            || $authentication['dkim_pass'] === false
            || $authentication['domain_alignment_pass'] === false;
    }

    /**
     * @param array<string, mixed> $intelligence
     */
    private function isExplicitProxyOrVpn(array $intelligence): bool
    {
        return ($intelligence['proxy'] ?? false) === true;
    }

    /**
     * @param array<string, mixed> $intelligence
     */
    private function buildProviderText(array $intelligence): string
    {
        return strtolower(trim(implode(' ', array_filter([
            $intelligence['isp'] ?? null,
            $intelligence['org'] ?? null,
            $intelligence['as'] ?? null,
            $intelligence['asname'] ?? null,
        ]))));
    }
}
