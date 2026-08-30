<?php

declare(strict_types=1);

namespace App\Support;

final class ThreatMetadata
{
    public const MAX_BYTES = 16384;

    public const MAX_DEPTH = 6;

    public const MAX_VALUES = 100;

    /**
     * @var list<string>
     */
    private const PROHIBITED_KEYS = [
        'api_key',
        'api_secret',
        'api_token',
        'attempted_account',
        'attempted_email',
        'attempted_identifier',
        'attempted_username',
        'authorization',
        'authorization_header',
        'card_number',
        'complete_request_body',
        'cookie',
        'cookies',
        'credential',
        'credentials',
        'credit_card',
        'cvv',
        'env_contents',
        'headers',
        'http_headers',
        'login_email',
        'login_identifier',
        'oauth_token',
        'password',
        'password_confirmation',
        'payment',
        'payment_details',
        'private_key',
        'raw_body',
        'request_body',
        'request_headers',
        'session',
        'session_id',
        'token',
    ];

    public static function isProhibitedKey(string $key): bool
    {
        $normalized = self::normalizedKey($key);

        if (in_array($normalized, self::PROHIBITED_KEYS, true)) {
            return true;
        }

        foreach ([
            'authorization',
            'card_number',
            'cookie',
            'credential',
            'credit_card',
            'env_content',
            'password',
            'private_key',
            'request_body',
            'secret',
            'session_id',
            'token',
        ] as $sensitiveFragment) {
            if (str_contains($normalized, $sensitiveFragment)) {
                return true;
            }
        }

        return false;
    }

    public static function isSafeMaskedIdentifier(mixed $value): bool
    {
        if (! is_string($value)) {
            return false;
        }

        return preg_match('/^[^@\s*]\*{3}@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i', trim($value)) === 1;
    }

    /**
     * Redact sensitive values defensively before metadata reaches an operator UI.
     * New API submissions reject these keys, but older/imported rows may not.
     *
     * @param  array<array-key, mixed>|null  $metadata
     * @return array<array-key, mixed>|null
     */
    public static function sanitized(?array $metadata): ?array
    {
        if ($metadata === null) {
            return null;
        }

        foreach ($metadata as $key => $value) {
            if (is_string($key) && self::isProhibitedKey($key)) {
                $metadata[$key] = '[redacted]';

                continue;
            }

            if (
                is_string($key)
                && self::normalizedKey($key) === 'attempted_identifier_masked'
                && ! self::isSafeMaskedIdentifier($value)
            ) {
                $metadata[$key] = '[redacted]';

                continue;
            }

            if (is_array($value)) {
                $metadata[$key] = self::sanitized($value);
            }
        }

        return $metadata;
    }

    private static function normalizedKey(string $key): string
    {
        return strtolower(trim((string) preg_replace('/[^a-zA-Z0-9]+/', '_', $key), '_'));
    }
}
