<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

class IpIntelligenceService
{
    private const TIMEOUT_SECONDS = 5;
    private const CACHE_TTL_SECONDS = 86400;

    /**
     * @return array{
     *     status: string,
     *     ip: string,
     *     country: string|null,
     *     countryCode: string|null,
     *     regionName: string|null,
     *     city: string|null,
     *     isp: string|null,
     *     org: string|null,
     *     as: string|null,
     *     mobile: bool,
     *     proxy: bool,
     *     hosting: bool,
     *     message: string|null
     * }
     */
    public function lookup(string $ipAddress): array
    {
        return Cache::remember(
            "ip_intelligence:{$ipAddress}",
            self::CACHE_TTL_SECONDS,
            fn (): array => $this->fetchIntelligence($ipAddress)
        );
    }

    /**
     * @return array{
     *     status: string,
     *     ip: string,
     *     country: string|null,
     *     countryCode: string|null,
     *     regionName: string|null,
     *     city: string|null,
     *     isp: string|null,
     *     org: string|null,
     *     as: string|null,
     *     mobile: bool,
     *     proxy: bool,
     *     hosting: bool,
     *     message: string|null
     * }
     */
    private function fetchIntelligence(string $ipAddress): array
    {
        try {
            $response = Http::timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->acceptJson()
                ->get("http://ip-api.com/json/{$ipAddress}", [
                    'fields' => 'status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting',
                ]);

            $payload = $response->json();

            if (!$response->successful() || !is_array($payload)) {
                return $this->buildFailurePayload($ipAddress, 'IP intelligence lookup failed.');
            }

            return [
                'status' => (string) ($payload['status'] ?? 'fail'),
                'ip' => $ipAddress,
                'country' => $this->nullableString($payload['country'] ?? null),
                'countryCode' => $this->nullableString($payload['countryCode'] ?? null),
                'regionName' => $this->nullableString($payload['regionName'] ?? null),
                'city' => $this->nullableString($payload['city'] ?? null),
                'isp' => $this->nullableString($payload['isp'] ?? null),
                'org' => $this->nullableString($payload['org'] ?? null),
                'as' => $this->nullableString($payload['as'] ?? null),
                'mobile' => (bool) ($payload['mobile'] ?? false),
                'proxy' => (bool) ($payload['proxy'] ?? false),
                'hosting' => (bool) ($payload['hosting'] ?? false),
                'message' => $this->nullableString($payload['message'] ?? null),
            ];
        } catch (ConnectionException $e) {
            return $this->buildFailurePayload($ipAddress, 'IP intelligence lookup timed out.');
        } catch (Throwable $e) {
            return $this->buildFailurePayload($ipAddress, 'Unexpected IP intelligence error: ' . $e->getMessage());
        }
    }

    /**
     * @return array{
     *     status: string,
     *     ip: string,
     *     country: string|null,
     *     countryCode: string|null,
     *     regionName: string|null,
     *     city: string|null,
     *     isp: string|null,
     *     org: string|null,
     *     as: string|null,
     *     mobile: bool,
     *     proxy: bool,
     *     hosting: bool,
     *     message: string|null
     * }
     */
    private function buildFailurePayload(string $ipAddress, string $message): array
    {
        return [
            'status' => 'fail',
            'ip' => $ipAddress,
            'country' => null,
            'countryCode' => null,
            'regionName' => null,
            'city' => null,
            'isp' => null,
            'org' => null,
            'as' => null,
            'mobile' => false,
            'proxy' => false,
            'hosting' => false,
            'message' => $message,
        ];
    }

    private function nullableString(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $normalized = trim($value);

        return $normalized !== '' ? $normalized : null;
    }
}
