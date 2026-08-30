<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\BlockedIp;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\ScannedEmail;
use App\Models\SecurityThreatLog;
use App\Models\User;
use App\Support\PortalContext;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class PlatformDashboardViewsTest extends TestCase
{
    use RefreshDatabase;

    public function test_security_overview_returns_aggregate_kpis_and_recent_activity(): void
    {
        $owner = $this->createPlatformUser(User::ROLE_PLATFORM_OWNER);
        [$activeDomain, $inactiveDomain] = $this->createMonitoredDomains();
        [$recentEvent, $olderEvent] = $this->createThreatEvents($activeDomain, $inactiveDomain);

        BlockedIp::create([
            'monitored_domain_id' => $activeDomain->id,
            'ip' => '203.0.113.50',
            'is_global' => false,
            'reason' => 'Repeated hostile requests',
        ]);

        $this->createEmailThreat($owner, 'high');
        $this->createEmailThreat($owner, 'medium');
        $this->createEmailThreat($owner, 'critical', false);

        $this->actingAs($owner)
            ->get(route('platform.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Dashboard')
                ->where('active_view', 'overview')
                ->where('security_overview.threat_events_total', 2)
                ->where('security_overview.threat_events_last_24_hours', 1)
                ->where('security_overview.email_threats_total', 2)
                ->where('security_overview.high_critical_email_threats', 1)
                ->where('security_overview.monitored_domains_total', 2)
                ->where('security_overview.active_monitored_domains', 1)
                ->where('security_overview.blocked_ips_total', 1)
                ->where('security_overview.pending_jobs', 0)
                ->where('security_overview.failed_jobs', 0)
                ->has('security_overview.recent_activity', 2)
                ->where('security_overview.recent_activity.0.id', $recentEvent->id)
                ->where('security_overview.recent_activity.1.id', $olderEvent->id)
                ->missing('threats'));
    }

    public function test_threat_overview_returns_investigable_security_telemetry_events(): void
    {
        $staff = $this->createPlatformUser(User::ROLE_PLATFORM_STAFF);
        [$activeDomain, $inactiveDomain] = $this->createMonitoredDomains();
        [$recentEvent] = $this->createThreatEvents($activeDomain, $inactiveDomain);

        $this->actingAs($staff)
            ->get(route('platform.dashboard', ['tab' => 'threats']))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Dashboard')
                ->where('active_view', 'threats')
                ->has('security_threat_events', 2)
                ->where('security_threat_events.0.id', $recentEvent->id)
                ->where('security_threat_events.0.threat_source', 'Cloudflare WAF')
                ->where('security_threat_events.0.attacker_ip', '203.0.113.10')
                ->where('security_threat_events.0.country', 'Ireland')
                ->where('security_threat_events.0.path_targeted', '/wp-login.php')
                ->where('security_threat_events.0.event_type', 'wordpress_admin_probe')
                ->where('security_threat_events.0.severity', 'medium')
                ->where('security_threat_events.0.reason', 'Probe for WordPress administrative endpoint')
                ->where('security_threat_events.0.metadata.matched_pattern', 'wp-admin')
                ->where('security_threat_events.0.metadata.password', '[redacted]')
                ->where('security_threat_events.0.action_taken', 'blocked')
                ->where('security_threat_events.0.monitored_domain.domain', $activeDomain->domain)
                ->where('security_threat_events.0.user_agent', 'Threat scanner agent')
                ->where('security_threat_events.1.event_type', null)
                ->where('security_threat_events.1.severity', null)
                ->where('security_threat_events.1.reason', null));
    }

    public function test_sidebar_links_select_distinct_dashboard_views(): void
    {
        $owner = $this->createPlatformUser(User::ROLE_PLATFORM_OWNER);
        $navigation = collect(PortalContext::for($owner)['sidebar_navigation'])->keyBy('key');

        $this->assertNull($navigation['security-overview']['parameters']);
        $this->assertSame(
            ['tab' => 'threats'],
            $navigation['threat-overview']['parameters']
        );

        $this->actingAs($owner)
            ->get(route('platform.dashboard', ['tab' => 'not-a-dashboard-view']))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->where('active_view', 'overview'));
    }

    private function createPlatformUser(string $role): User
    {
        $company = Company::create([
            'name' => fake()->unique()->company(),
            'domain' => fake()->unique()->domainName(),
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);

        return User::factory()->create([
            'company_id' => $company->id,
            'role' => $role,
        ]);
    }

    /**
     * @return array{MonitoredDomain, MonitoredDomain}
     */
    private function createMonitoredDomains(): array
    {
        $company = Company::create([
            'name' => fake()->unique()->company(),
            'domain' => fake()->unique()->domainName(),
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);

        return [
            MonitoredDomain::create([
                'company_id' => $company->id,
                'domain' => 'active.example.test',
                'infrastructure_type' => 'app_middleware',
                'is_active' => true,
            ]),
            MonitoredDomain::create([
                'company_id' => $company->id,
                'domain' => 'inactive.example.test',
                'infrastructure_type' => 'cloudflare',
                'is_active' => false,
            ]),
        ];
    }

    /**
     * @return array{SecurityThreatLog, SecurityThreatLog}
     */
    private function createThreatEvents(
        MonitoredDomain $activeDomain,
        MonitoredDomain $inactiveDomain
    ): array {
        return [
            SecurityThreatLog::create([
                'monitored_domain_id' => $activeDomain->id,
                'attacker_ip' => '203.0.113.10',
                'country' => 'Ireland',
                'path_targeted' => '/wp-login.php',
                'user_agent' => 'Threat scanner agent',
                'event_type' => 'wordpress_admin_probe',
                'severity' => 'medium',
                'reason' => 'Probe for WordPress administrative endpoint',
                'metadata' => [
                    'matched_pattern' => 'wp-admin',
                    'password' => 'must-not-reach-the-ui',
                ],
                'action_taken' => 'blocked',
                'threat_source' => 'Cloudflare WAF',
                'detected_at' => now()->subHour(),
            ]),
            SecurityThreatLog::create([
                'monitored_domain_id' => $inactiveDomain->id,
                'attacker_ip' => '198.51.100.20',
                'country' => 'Germany',
                'path_targeted' => '/admin',
                'user_agent' => 'Reconnaissance bot',
                'action_taken' => 'challenged',
                'threat_source' => 'Application Middleware',
                'detected_at' => now()->subDays(2),
            ]),
        ];
    }

    private function createEmailThreat(User $user, string $severity, bool $isThreat = true): ScannedEmail
    {
        return ScannedEmail::create([
            'user_id' => $user->id,
            'google_message_id' => fake()->unique()->uuid(),
            'subject' => 'Security test email',
            'sender' => 'sender@example.test',
            'snippet' => 'Test content',
            'is_threat' => $isThreat,
            'severity' => $severity,
            'risk_score' => $isThreat ? 80 : 0,
        ]);
    }
}
