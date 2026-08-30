<?php

declare(strict_types=1);

namespace App\Support;

use App\Models\User;

final class PortalContext
{
    public const EXPERIENCE_PLATFORM = 'platform';

    public const EXPERIENCE_CLIENT_ADMIN = 'client_admin';

    public const EXPERIENCE_CLIENT_USER = 'client_user';

    public const EXPERIENCE_LEGACY = 'legacy';

    /**
     * @return array<string, mixed>
     */
    public static function for(?User $user): array
    {
        $experience = self::experienceFor($user);
        $company = $experience !== self::EXPERIENCE_LEGACY
            ? $user?->company
            : null;

        return [
            'experience' => $experience,
            'title' => self::titleFor($experience),
            'company' => $company ? [
                'id' => $company->id,
                'name' => $company->name,
                'type' => $company->type,
                'status' => $company->status,
            ] : null,
            'landing_route' => self::landingRouteName($user),
            'can_access_platform' => $user?->hasPlatformAccess() ?? false,
            'can_manage_platform_users' => $user?->hasPlatformOwnerAccess() ?? false,
            'navigation' => self::topNavigationFor($experience),
            'sidebar_navigation' => self::sidebarNavigationFor(
                $experience,
                $user?->hasPlatformOwnerAccess() ?? false
            ),
        ];
    }

    public static function experienceFor(?User $user): string
    {
        return match (true) {
            $user?->hasPlatformAccess() => self::EXPERIENCE_PLATFORM,
            $user?->hasClientAdminPortalAccess() => self::EXPERIENCE_CLIENT_ADMIN,
            $user?->hasClientUserPortalAccess() => self::EXPERIENCE_CLIENT_USER,
            default => self::EXPERIENCE_LEGACY,
        };
    }

    public static function landingRouteName(?User $user): string
    {
        return match (self::experienceFor($user)) {
            self::EXPERIENCE_PLATFORM => 'platform.dashboard',
            self::EXPERIENCE_CLIENT_ADMIN => 'company.dashboard',
            default => 'dashboard',
        };
    }

    private static function titleFor(string $experience): string
    {
        return match ($experience) {
            self::EXPERIENCE_PLATFORM => 'Platform Security Console',
            self::EXPERIENCE_CLIENT_ADMIN => 'Security Portal',
            self::EXPERIENCE_CLIENT_USER => 'My Security',
            default => 'Personal Security',
        };
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private static function topNavigationFor(string $experience): array
    {
        if ($experience === self::EXPERIENCE_PLATFORM) {
            return [];
        }

        $navigation = [
            self::navigationItem('email-security', 'Email Security', 'dashboard', 'My Security'),
            self::navigationItem('sms-scanner', 'SMS Scanner', 'sms.index', 'My Security'),
        ];

        if ($experience === self::EXPERIENCE_CLIENT_ADMIN) {
            $navigation[] = self::navigationItem(
                'company-threat-review',
                'Threat Review',
                'company.threats.index',
                'Company Security',
                ['company.threats.*']
            );
        }

        $navigation[] = self::navigationItem('profile', 'Profile', 'profile.edit', 'Account');

        return $navigation;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private static function sidebarNavigationFor(string $experience, bool $canManagePlatformUsers): array
    {
        if ($experience !== self::EXPERIENCE_PLATFORM) {
            return [];
        }

        $navigation = [
            self::navigationItem(
                'security-overview',
                'Security Overview',
                'platform.dashboard',
                'Overviews',
                ['platform.dashboard', 'admin.dashboard']
            ),
            self::navigationItem(
                'threat-overview',
                'Threat Overview',
                'platform.dashboard',
                'Overviews',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'threats']
            ),
            self::navigationItem('dns-security', 'DNS Security', 'dns-security.index', 'Infrastructure Security', ['dns-security.*']),
            self::navigationItem(
                'tier-3-protection',
                'Tier 3 Protection',
                'platform.dashboard',
                'Infrastructure Security',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'tier3']
            ),
            self::navigationItem('blocked-ips', 'Blocked IPs', 'admin.blocked-ips.index', 'Infrastructure Security', ['admin.blocked-ips.*']),
            self::navigationItem(
                'whitelist-manager',
                'Whitelist Manager',
                'platform.dashboard',
                'Infrastructure Security',
                ['platform.dashboard', 'admin.dashboard', 'domains.*'],
                ['tab' => 'domains']
            ),
            self::navigationItem(
                'global-intelligence',
                'Global Intelligence',
                'platform.dashboard',
                'Intelligence & Reporting',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'intelligence']
            ),
            self::navigationItem(
                'reports-analytics',
                'Reports & Analytics',
                'platform.dashboard',
                'Intelligence & Reporting',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'reports']
            ),
            self::navigationItem(
                'audit-trail',
                'Audit Trail',
                'platform.dashboard',
                'Intelligence & Reporting',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'audit']
            ),
            self::navigationItem(
                'system-health',
                'System Health',
                'platform.dashboard',
                'Platform Operations',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'system']
            ),
            self::navigationItem('email-security', 'Email Security', 'dashboard', 'Personal Tools'),
            self::navigationItem('sms-scanner', 'SMS Scanner', 'sms.index', 'Personal Tools'),
        ];

        if ($canManagePlatformUsers) {
            $navigation[] = self::navigationItem(
                'client-companies',
                'Client Companies',
                'platform.client-companies.index',
                'Management',
                ['platform.client-companies.*']
            );
            $navigation[] = self::navigationItem(
                'platform-staff',
                'Platform Staff',
                'platform.dashboard',
                'Management',
                ['platform.dashboard', 'admin.dashboard'],
                ['tab' => 'users']
            );
        }

        $navigation[] = self::navigationItem('profile', 'Profile', 'profile.edit', 'Account');

        return $navigation;
    }

    /**
     * @param  array<int, string>|null  $activeRoutes
     * @param  array<string, string>|null  $parameters
     * @return array<string, mixed>
     */
    private static function navigationItem(
        string $key,
        string $label,
        string $route,
        string $section,
        ?array $activeRoutes = null,
        ?array $parameters = null
    ): array {
        return [
            'key' => $key,
            'label' => $label,
            'route' => $route,
            'section' => $section,
            'active_routes' => $activeRoutes ?? [$route],
            'parameters' => $parameters,
        ];
    }
}
