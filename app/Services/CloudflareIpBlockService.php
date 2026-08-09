<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Throwable;

class CloudflareIpBlockService
{
    private const TIMEOUT_SECONDS = 5;

    /**
     * @return array{
     *     success: bool,
     *     message: string,
     *     rules: list<array{
     *         id: string,
     *         ip_address: string,
     *         notes: string|null,
     *         created_on: string|null
     *     }>
     * }
     */
    public function listAccessRules(string $zoneId): array
    {
        $token = trim((string) config('services.cloudflare.api_token', ''));

        if ($token === '') {
            return [
                'success' => false,
                'message' => 'Cloudflare API token is not configured.',
                'rules' => [],
            ];
        }

        try {
            $response = Http::withToken($token)
                ->acceptJson()
                ->timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->get(
                    "https://api.cloudflare.com/client/v4/zones/{$zoneId}/firewall/access_rules/rules",
                    ['mode' => 'block']
                );

            $payload = $response->json();

            if ($response->failed() || !($payload['success'] ?? false)) {
                $message = $this->resolveCloudflareErrorMessage($payload);

                return [
                    'success' => false,
                    'message' => $message !== '' ? $message : 'Cloudflare rejected the access rule lookup request.',
                    'rules' => [],
                ];
            }

            /** @var list<array<string, mixed>> $rules */
            $rules = is_array($payload['result'] ?? null) ? $payload['result'] : [];

            return [
                'success' => true,
                'message' => 'Access rules loaded successfully.',
                'rules' => collect($rules)
                    ->map(fn (array $rule): array => [
                        'id' => (string) data_get($rule, 'id', ''),
                        'ip_address' => (string) data_get($rule, 'configuration.value', ''),
                        'notes' => $this->nullableString(data_get($rule, 'notes')),
                        'created_on' => $this->nullableString(data_get($rule, 'created_on')),
                    ])
                    ->filter(fn (array $rule): bool => $rule['id'] !== '' && $rule['ip_address'] !== '')
                    ->values()
                    ->all(),
            ];
        } catch (ConnectionException $e) {
            return [
                'success' => false,
                'message' => 'Cloudflare did not respond within 5 seconds.',
                'rules' => [],
            ];
        } catch (Throwable $e) {
            return [
                'success' => false,
                'message' => 'Unexpected Cloudflare error: ' . $e->getMessage(),
                'rules' => [],
            ];
        }
    }

    /**
     * @return array{success: bool, message: string, rule_id: string|null}
     */
    public function blockIp(string $zoneId, string $attackerIp): array
    {
        $token = trim((string) config('services.cloudflare.api_token', ''));

        if ($token === '') {
            return [
                'success' => false,
                'message' => 'Cloudflare API token is not configured.',
                'rule_id' => null,
            ];
        }

        try {
            $response = Http::withToken($token)
                ->acceptJson()
                ->timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->post(
                    "https://api.cloudflare.com/client/v4/zones/{$zoneId}/firewall/access_rules/rules",
                    [
                        'mode' => 'block',
                        'configuration' => [
                            'target' => 'ip',
                            'value' => $attackerIp,
                        ],
                        'notes' => 'Blocked via DNS Security Dashboard',
                    ]
                );

            $payload = $response->json();

            if ($response->failed() || !($payload['success'] ?? false)) {
                $message = $this->resolveCloudflareErrorMessage($payload);

                return [
                    'success' => false,
                    'message' => $message !== '' ? $message : 'Cloudflare rejected the IP block request.',
                    'rule_id' => null,
                ];
            }

            return [
                'success' => true,
                'message' => 'IP blocked successfully on Cloudflare.',
                'rule_id' => data_get($payload, 'result.id'),
            ];
        } catch (ConnectionException $e) {
            return [
                'success' => false,
                'message' => 'Cloudflare did not respond within 5 seconds.',
                'rule_id' => null,
            ];
        } catch (Throwable $e) {
            return [
                'success' => false,
                'message' => 'Unexpected Cloudflare error: ' . $e->getMessage(),
                'rule_id' => null,
            ];
        }
    }

    /**
     * @return array{success: bool, message: string}
     */
    public function deleteAccessRule(string $zoneId, string $ruleId): array
    {
        $token = trim((string) config('services.cloudflare.api_token', ''));

        if ($token === '') {
            return [
                'success' => false,
                'message' => 'Cloudflare API token is not configured.',
            ];
        }

        try {
            $response = Http::withToken($token)
                ->acceptJson()
                ->timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->delete("https://api.cloudflare.com/client/v4/zones/{$zoneId}/firewall/access_rules/rules/{$ruleId}");

            $payload = $response->json();

            if ($response->failed() || !($payload['success'] ?? false)) {
                $message = $this->resolveCloudflareErrorMessage($payload);

                return [
                    'success' => false,
                    'message' => $message !== '' ? $message : 'Cloudflare rejected the unblock request.',
                ];
            }

            return [
                'success' => true,
                'message' => 'IP access rule removed successfully on Cloudflare.',
            ];
        } catch (ConnectionException $e) {
            return [
                'success' => false,
                'message' => 'Cloudflare did not respond within 5 seconds.',
            ];
        } catch (Throwable $e) {
            return [
                'success' => false,
                'message' => 'Unexpected Cloudflare error: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function resolveCloudflareErrorMessage(array $payload): string
    {
        $errors = $payload['errors'] ?? null;

        if (!is_array($errors)) {
            return '';
        }

        return collect($errors)
            ->map(static fn (mixed $error): string => (string) data_get($error, 'message', ''))
            ->filter()
            ->implode('; ');
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
