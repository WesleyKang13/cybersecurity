<?php

declare(strict_types=1);

namespace App\Support;

final class ThreatEventPresentation
{
    public static function actionLabel(?string $action): string
    {
        return match (self::normalized($action)) {
            'block', 'blocked' => 'Blocked',
            'challenge', 'challenged', 'js_challenge', 'managed_challenge' => 'Challenged',
            'log', 'logged' => 'Logged',
            'allow', 'allowed' => 'Allowed',
            '' => 'Outcome not reported',
            default => self::humanize($action),
        };
    }

    public static function actionOutcome(?string $action): string
    {
        return match (self::normalized($action)) {
            'block', 'blocked' => 'blocked',
            'challenge', 'challenged', 'js_challenge', 'managed_challenge' => 'challenged',
            'log', 'logged' => 'logged',
            'allow', 'allowed' => 'allowed',
            default => 'reported',
        };
    }

    public static function sourceLabel(?string $source): string
    {
        $normalized = self::normalized($source);

        if (in_array($normalized, ['app_middleware', 'application_middleware'], true)) {
            return 'Tier 3 Application Middleware';
        }

        if (
            in_array($normalized, ['access_rule', 'access_rules', 'accessrules', 'ip_access_rule', 'ip_access_rules', 'ipaccessrules'], true)
            || str_contains($normalized, 'access_rule')
        ) {
            return 'Cloudflare IP Access Rules';
        }

        if (
            in_array($normalized, ['firewall_managed', 'managed_rules', 'waf_managed_rules'], true)
            || str_contains($normalized, 'managed')
        ) {
            return 'Cloudflare WAF Managed Rules';
        }

        if (in_array($normalized, ['cloudflare', 'cloudflare_waf', 'firewall'], true)) {
            return 'Cloudflare WAF';
        }

        return $normalized === '' ? 'Source not reported' : self::humanize($source);
    }

    public static function sourceKind(?string $source): string
    {
        $normalized = self::normalized($source);

        if (in_array($normalized, ['app_middleware', 'application_middleware'], true)) {
            return 'tier_3_middleware';
        }

        if (str_contains($normalized, 'access_rule') || in_array($normalized, ['accessrules', 'ipaccessrules'], true)) {
            return 'cloudflare_ip_access_rule';
        }

        if (str_contains($normalized, 'managed')) {
            return 'cloudflare_waf_managed_rule';
        }

        if (in_array($normalized, ['cloudflare', 'cloudflare_waf', 'firewall'], true)) {
            return 'cloudflare_waf';
        }

        return 'unclassified';
    }

    private static function normalized(?string $value): string
    {
        return strtolower(trim((string) $value));
    }

    private static function humanize(?string $value): string
    {
        $words = preg_split('/[_\-\s]+/', trim((string) $value)) ?: [];

        return collect($words)
            ->filter()
            ->map(static fn (string $word): string => ucfirst($word))
            ->implode(' ') ?: 'Not reported';
    }
}
