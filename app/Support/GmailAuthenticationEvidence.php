<?php

declare(strict_types=1);

namespace App\Support;

use Google\Service\Gmail\MessagePartHeader;

/**
 * Authentication data derived at the Gmail API boundary.
 *
 * The scanner receives this object only from GmailService; manual JSON payloads
 * cannot manufacture it. The Gmail API preserves RFC 2822 header order, where
 * each receiving system prepends its own headers. Therefore only the first
 * Authentication-Results header can be Gmail's receiving-provider result. A
 * missing, conflicting, or non-Gmail first result intentionally yields no
 * evidence rather than trusting a sender-provided header further down the list.
 */
final readonly class GmailAuthenticationEvidence
{
    public function __construct(
        public ?string $dmarcResult,
        public ?string $dmarcDomain,
        public ?string $spfResult,
        public ?string $spfDomain,
        public ?string $dkimResult,
        public ?string $dkimDomain
    ) {}

    /**
     * @param  array<int, MessagePartHeader>  $headers
     */
    public static function fromGmailHeaders(array $headers): ?self
    {
        foreach ($headers as $header) {
            if (strtolower((string) $header->getName()) !== 'authentication-results') {
                continue;
            }

            return self::fromFirstAuthenticationResults((string) $header->getValue());
        }

        return null;
    }

    private static function fromFirstAuthenticationResults(string $value): ?self
    {
        // Do not accept an arbitrary authserv-id merely because it reports pass.
        if (! preg_match('/^\s*(?:mx\.google\.com|gmail\.com)\s*;/i', $value)) {
            return null;
        }

        return new self(
            dmarcResult: self::extractResult($value, 'dmarc'),
            dmarcDomain: self::extractSingleDomain($value, 'header\.from'),
            spfResult: self::extractResult($value, 'spf'),
            spfDomain: self::extractSingleDomain($value, 'smtp\.mailfrom', true),
            dkimResult: self::extractResult($value, 'dkim'),
            dkimDomain: self::extractSingleDomain($value, 'header\.i', true),
        );
    }

    private static function extractResult(string $value, string $mechanism): ?string
    {
        preg_match_all(
            '/\b'.preg_quote($mechanism, '/').'=(pass|fail|softfail|temperror|permerror|neutral|none)\b/i',
            $value,
            $matches
        );
        $results = array_values(array_unique(array_map('strtolower', $matches[1] ?? [])));

        if (count($results) !== 1) {
            return null;
        }

        return $results[0];
    }

    private static function extractSingleDomain(string $value, string $attribute, bool $extractEmailDomain = false): ?string
    {
        preg_match_all('/\b'.$attribute.'=([^\s;]+)/i', $value, $matches);
        $domains = array_values(array_unique(array_map(function (string $domain) use ($extractEmailDomain) {
            $normalized = trim($domain, " \t\n\r\0\x0B.\"'");

            if ($extractEmailDomain && str_contains($normalized, '@')) {
                $normalized = substr($normalized, (int) strrpos($normalized, '@') + 1);
            }

            return strtolower(trim($normalized, " \t\n\r\0\x0B.\"'"));
        }, $matches[1] ?? [])));

        return count($domains) === 1 && $domains[0] !== '' ? $domains[0] : null;
    }
}
