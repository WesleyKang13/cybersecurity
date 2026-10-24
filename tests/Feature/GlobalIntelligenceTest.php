<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\BlockedIp;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Models\User;
use App\Services\CloudflareIpBlockService;
use App\Services\IpIntelligenceService;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Inertia\Testing\AssertableInertia as Assert;
use Mockery\MockInterface;
use Tests\TestCase;

class GlobalIntelligenceTest extends TestCase
{
    use RefreshDatabase;

    public function test_global_intelligence_remains_platform_only_for_both_roles(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platformCompany, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($platformCompany, User::ROLE_PLATFORM_STAFF);
        $clientAdmin = $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN);
        $clientUser = $this->createUser($clientCompany, User::ROLE_CLIENT_USER);

        $this->mockIpIntelligence();

        foreach ([$owner, $staff] as $platformUser) {
            $this->actingAs($platformUser)
                ->get(route('platform.dashboard', ['tab' => 'intelligence']))
                ->assertOk()
                ->assertInertia(fn (Assert $page) => $page
                    ->component('Admin/Dashboard')
                    ->where('active_view', 'intelligence'));

            $this->actingAs($platformUser)
                ->getJson(route('admin.ip-intelligence', '203.0.113.10'))
                ->assertOk();
        }

        foreach ([$clientAdmin, $clientUser] as $clientRole) {
            $this->actingAs($clientRole)
                ->get(route('platform.dashboard', ['tab' => 'intelligence']))
                ->assertForbidden();

            $this->actingAs($clientRole)
                ->getJson(route('admin.ip-intelligence', '203.0.113.10'))
                ->assertForbidden();
        }
    }

    public function test_ip_investigation_combines_normalized_intelligence_with_scoped_observations(): void
    {
        $staff = $this->createUser(
            $this->createCompany(Company::TYPE_PLATFORM),
            User::ROLE_PLATFORM_STAFF
        );
        $firstDomain = $this->createDomain('app-one.example.test');
        $secondDomain = $this->createDomain('app-two.example.test');
        $attackerIp = '203.0.113.10';

        $this->createThreatEvent($firstDomain, $attackerIp, '2026-08-01 10:00:00', [
            'event_type' => 'wordpress_probe',
            'severity' => 'medium',
            'path_targeted' => '/wp-login.php',
            'action_taken' => 'blocked',
            'threat_source' => 'cloudflare',
        ]);
        $this->createThreatEvent($firstDomain, $attackerIp, '2026-08-02 11:00:00', [
            'event_type' => 'wordpress_probe',
            'severity' => 'medium',
            'path_targeted' => '/wp-admin',
            'action_taken' => 'challenged',
            'threat_source' => 'cloudflare',
        ]);
        $this->createThreatEvent($firstDomain, $attackerIp, '2026-08-03 12:00:00', [
            'event_type' => null,
            'severity' => null,
            'path_targeted' => null,
            'action_taken' => 'logged',
            'threat_source' => null,
        ]);
        $this->createThreatEvent($secondDomain, $attackerIp, '2026-08-04 13:00:00', [
            'event_type' => 'failed_login',
            'severity' => 'high',
            'path_targeted' => '/login',
            'action_taken' => 'logged',
            'threat_source' => 'app_middleware',
        ]);
        $this->createThreatEvent($secondDomain, '198.51.100.25', '2026-08-05 14:00:00', [
            'event_type' => 'environment_probe',
            'severity' => 'critical',
            'path_targeted' => '/.env',
            'action_taken' => 'blocked',
            'threat_source' => 'app_middleware',
        ]);

        BlockedIp::create([
            'monitored_domain_id' => $secondDomain->id,
            'ip' => $attackerIp,
            'is_global' => false,
            'reason' => 'Repeated login attempts',
        ]);

        $this->mockIpIntelligence();

        $response = $this->actingAs($staff)
            ->getJson(route('admin.ip-intelligence', $attackerIp))
            ->assertOk()
            ->assertJsonPath('success', true)
            ->assertJsonPath('data.status', 'success')
            ->assertJsonPath('data.ip', $attackerIp)
            ->assertJsonPath('data.country', 'Exampleland')
            ->assertJsonPath('data.countryCode', 'EX')
            ->assertJsonPath('data.regionName', 'Example Region')
            ->assertJsonPath('data.city', 'Example City')
            ->assertJsonPath('data.isp', 'Example ISP')
            ->assertJsonPath('data.org', 'Example Organization')
            ->assertJsonPath('data.as', 'AS64500 Example Network')
            ->assertJsonPath('data.mobile', false)
            ->assertJsonPath('data.proxy', true)
            ->assertJsonPath('data.hosting', true)
            ->assertJsonPath('data.observations.total_events', 4)
            ->assertJsonPath('data.observations.applications_targeted', 2)
            ->assertJsonPath('data.observations.first_seen', '2026-08-01T10:00:00+00:00')
            ->assertJsonPath('data.observations.last_seen', '2026-08-04T13:00:00+00:00')
            ->assertJsonPath('data.observations.top_applications.0.domain', 'app-one.example.test')
            ->assertJsonPath('data.observations.top_applications.0.count', 3)
            ->assertJsonPath('data.observations.top_applications.1.domain', 'app-two.example.test')
            ->assertJsonPath('data.observations.top_applications.1.count', 1)
            ->assertJsonPath('data.observations.threat_types.0.value', 'wordpress_probe')
            ->assertJsonPath('data.observations.threat_types.0.count', 2)
            ->assertJsonPath('data.block_status.classification', 'tier3_domain_block_list_entry')
            ->assertJsonPath('data.block_status.verified_locations.0.tier', 'Tier 3')
            ->assertJsonPath('data.block_status.verified_locations.0.source', 'Tier 3 domain block list')
            ->assertJsonPath('data.block_status.verified_locations.0.domain', 'app-two.example.test')
            ->assertJsonPath('data.block_status.tier_3.classification', 'domain_block_list_entry')
            ->assertJsonPath('data.block_status.tier_3.domain_block_list_entries.0.domain', 'app-two.example.test')
            ->assertJsonPath('data.block_status.tier_2.status', 'not_configured')
            ->assertJsonPath('data.observations.recent_activity.0.action_label', 'Logged');

        $response->assertJsonFragment(['value' => 'failed_login', 'count' => 1]);
        $response->assertJsonFragment(['value' => 'unclassified', 'count' => 1]);
        $response->assertJsonMissing(['value' => 'environment_probe']);
    }

    public function test_valid_ip_search_returns_fields_normalized_by_the_existing_ip_service(): void
    {
        $staff = $this->createUser(
            $this->createCompany(Company::TYPE_PLATFORM),
            User::ROLE_PLATFORM_STAFF
        );
        $ipAddress = '192.0.2.55';
        Cache::forget("ip_intelligence:{$ipAddress}");
        Http::fake([
            'http://ip-api.com/*' => Http::response([
                'status' => 'success',
                'country' => 'United Kingdom',
                'countryCode' => 'GB',
                'regionName' => 'England',
                'city' => 'London',
                'isp' => 'Provider Ltd',
                'org' => 'Network Operations',
                'as' => 'AS64501 Provider Ltd',
                'mobile' => false,
                'proxy' => false,
                'hosting' => true,
            ]),
        ]);

        $this->actingAs($staff)
            ->getJson(route('admin.ip-intelligence', $ipAddress))
            ->assertOk()
            ->assertJsonPath('data.ip', $ipAddress)
            ->assertJsonPath('data.country', 'United Kingdom')
            ->assertJsonPath('data.countryCode', 'GB')
            ->assertJsonPath('data.regionName', 'England')
            ->assertJsonPath('data.city', 'London')
            ->assertJsonPath('data.isp', 'Provider Ltd')
            ->assertJsonPath('data.org', 'Network Operations')
            ->assertJsonPath('data.as', 'AS64501 Provider Ltd')
            ->assertJsonPath('data.mobile', false)
            ->assertJsonPath('data.proxy', false)
            ->assertJsonPath('data.hosting', true);
    }

    public function test_block_status_distinguishes_tier_three_entries_and_unknown_cloudflare_status(): void
    {
        $owner = $this->createUser(
            $this->createCompany(Company::TYPE_PLATFORM),
            User::ROLE_PLATFORM_OWNER
        );
        $domain = $this->createDomain('blocked.example.test');

        BlockedIp::create([
            'monitored_domain_id' => null,
            'ip' => '203.0.113.40',
            'is_global' => true,
            'reason' => 'Platform-wide block',
        ]);
        BlockedIp::create([
            'monitored_domain_id' => $domain->id,
            'ip' => '203.0.113.41',
            'is_global' => false,
            'reason' => 'Application-only block',
        ]);

        $this->mockIpIntelligence();

        $this->actingAs($owner)
            ->getJson(route('admin.ip-intelligence', '203.0.113.40'))
            ->assertOk()
            ->assertJsonPath('data.block_status.classification', 'tier3_global_block_list_entry')
            ->assertJsonPath('data.block_status.tier_3.global_block_list_entry', true);

        $this->actingAs($owner)
            ->getJson(route('admin.ip-intelligence', '203.0.113.41'))
            ->assertOk()
            ->assertJsonPath('data.block_status.classification', 'tier3_domain_block_list_entry')
            ->assertJsonPath('data.block_status.tier_3.domain_block_list_entries.0.domain', 'blocked.example.test');

        $this->actingAs($owner)
            ->getJson(route('admin.ip-intelligence', '203.0.113.42'))
            ->assertOk()
            ->assertJsonPath('data.block_status.classification', 'no_known_block')
            ->assertJsonPath('data.block_status.tier_3.global_block_list_entry', false)
            ->assertJsonCount(0, 'data.block_status.tier_3.domain_block_list_entries');
    }

    public function test_ip_investigation_lists_verified_locations_from_each_block_source_without_telemetry(): void
    {
        $owner = $this->createUser($this->createCompany(Company::TYPE_PLATFORM), User::ROLE_PLATFORM_OWNER);
        $cloudflareDomain = $this->createDomain('edge.example.test', [
            'infrastructure_type' => 'cloudflare',
            'is_owned' => true,
            'cloudflare_zone_id' => 'zone-123',
        ]);
        $tier3Domain = $this->createDomain('tier-three.example.test');
        $attackerIp = '203.0.113.99';

        BlockedIp::create([
            'ip' => $attackerIp,
            'is_global' => true,
            'reason' => 'Platform-wide block',
        ]);
        BlockedIp::create([
            'monitored_domain_id' => $tier3Domain->id,
            'ip' => $attackerIp,
            'is_global' => false,
            'reason' => 'Application-only block',
        ]);

        $this->mockIpIntelligence();
        $this->mock(CloudflareIpBlockService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('listAccessRules')->once()->with('zone-123')->andReturn([
                'success' => true,
                'message' => 'Access rules loaded successfully.',
                'rules' => [[
                    'id' => 'rule-123',
                    'ip_address' => '203.0.113.99',
                    'notes' => 'Test block',
                    'created_on' => '2026-10-13T12:00:00Z',
                ]],
            ]);
        });

        $this->actingAs($owner)
            ->getJson(route('admin.ip-intelligence', $attackerIp))
            ->assertOk()
            ->assertJsonPath('data.block_status.classification', 'cloudflare_ip_access_rule_active')
            ->assertJsonPath('data.block_status.tier_2.status', 'active')
            ->assertJsonPath('data.block_status.tier_2.active_ip_access_rules.0.domain', $cloudflareDomain->domain)
            ->assertJsonCount(3, 'data.block_status.verified_locations')
            ->assertJsonPath('data.block_status.verified_locations.0.tier', 'Tier 2')
            ->assertJsonPath('data.block_status.verified_locations.0.source', 'Cloudflare IP Access Rule')
            ->assertJsonPath('data.block_status.verified_locations.0.domain', $cloudflareDomain->domain)
            ->assertJsonPath('data.block_status.verified_locations.0.rule_id', 'rule-123')
            ->assertJsonPath('data.block_status.verified_locations.1.tier', 'Tier 3')
            ->assertJsonPath('data.block_status.verified_locations.1.source', 'Tier 3 global block list')
            ->assertJsonPath('data.block_status.verified_locations.1.domain', null)
            ->assertJsonPath('data.block_status.verified_locations.2.source', 'Tier 3 domain block list')
            ->assertJsonPath('data.block_status.verified_locations.2.domain', $tier3Domain->domain);
    }

    public function test_ip_investigation_does_not_treat_a_reported_block_as_a_verified_location(): void
    {
        $owner = $this->createUser($this->createCompany(Company::TYPE_PLATFORM), User::ROLE_PLATFORM_OWNER);
        $domain = $this->createDomain('observed-edge.example.test', [
            'infrastructure_type' => 'cloudflare',
            'is_owned' => true,
            'cloudflare_zone_id' => 'zone-456',
        ]);
        $attackerIp = '203.0.113.98';

        $this->mockIpIntelligence();
        $this->createThreatEvent($domain, $attackerIp, '2026-10-13 11:59:00', [
            'threat_source' => 'firewallManaged',
            'action_taken' => 'block',
        ]);
        $this->mock(CloudflareIpBlockService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('listAccessRules')->once()->with('zone-456')->andReturn([
                'success' => true,
                'message' => 'Access rules loaded successfully.',
                'rules' => [],
            ]);
        });

        $this->actingAs($owner)
            ->getJson(route('admin.ip-intelligence', $attackerIp))
            ->assertOk()
            ->assertJsonPath('data.block_status.classification', 'no_known_block')
            ->assertJsonPath('data.block_status.tier_2.status', 'not_active')
            ->assertJsonCount(0, 'data.block_status.verified_locations');
    }

    public function test_global_intelligence_dashboard_returns_attacker_rollups_instead_of_event_rows(): void
    {
        $owner = $this->createUser(
            $this->createCompany(Company::TYPE_PLATFORM),
            User::ROLE_PLATFORM_OWNER
        );
        $firstDomain = $this->createDomain('primary.example.test');
        $secondDomain = $this->createDomain('secondary.example.test');

        $this->createThreatEvent($firstDomain, '203.0.113.70', '2026-08-10 10:00:00');
        $this->createThreatEvent($secondDomain, '203.0.113.70', '2026-08-11 10:00:00', [
            'path_targeted' => '/different-path',
        ]);
        $this->createThreatEvent($firstDomain, '198.51.100.70', '2026-08-12 10:00:00');
        BlockedIp::create([
            'monitored_domain_id' => null,
            'ip' => '203.0.113.70',
            'is_global' => true,
        ]);

        $this->actingAs($owner)
            ->get(route('platform.dashboard', ['tab' => 'intelligence']))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('active_view', 'intelligence')
                ->has('top_attackers', 2)
                ->where('top_attackers.0.attacker_ip', '203.0.113.70')
                ->where('top_attackers.0.total_events', 2)
                ->where('top_attackers.0.applications_targeted', 2)
                ->where('top_attackers.0.tier_3_status', 'global_block_list_entry')
                ->has('security_threat_events', 0)
                ->has('tier_3_domains', 0)
                ->missing('top_targeted_paths')
                ->missing('top_attacker_ips'));
    }

    private function mockIpIntelligence(): void
    {
        $this->mock(IpIntelligenceService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('lookup')
                ->andReturnUsing(fn (string $ipAddress): array => [
                    'status' => 'success',
                    'ip' => $ipAddress,
                    'country' => 'Exampleland',
                    'countryCode' => 'EX',
                    'regionName' => 'Example Region',
                    'city' => 'Example City',
                    'isp' => 'Example ISP',
                    'org' => 'Example Organization',
                    'as' => 'AS64500 Example Network',
                    'mobile' => false,
                    'proxy' => true,
                    'hosting' => true,
                    'message' => null,
                ]);
        });
    }

    private function createCompany(string $type): Company
    {
        return Company::create([
            'name' => fake()->unique()->company(),
            'domain' => fake()->unique()->domainName(),
            'type' => $type,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
    }

    private function createUser(Company $company, string $role): User
    {
        return User::factory()->create([
            'company_id' => $company->id,
            'role' => $role,
        ]);
    }

    private function createDomain(string $domain, array $overrides = []): MonitoredDomain
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);

        return MonitoredDomain::create(array_merge([
            'company_id' => $company->id,
            'domain' => $domain,
            'infrastructure_type' => 'app_middleware',
            'is_active' => true,
        ], $overrides));
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function createThreatEvent(
        MonitoredDomain $domain,
        string $attackerIp,
        string $detectedAt,
        array $overrides = []
    ): SecurityThreatLog {
        return SecurityThreatLog::create(array_merge([
            'monitored_domain_id' => $domain->id,
            'attacker_ip' => $attackerIp,
            'country' => 'Exampleland',
            'path_targeted' => '/login',
            'event_type' => 'failed_login',
            'severity' => 'medium',
            'action_taken' => 'logged',
            'threat_source' => 'app_middleware',
            'detected_at' => CarbonImmutable::parse($detectedAt, 'UTC'),
        ], $overrides));
    }
}
