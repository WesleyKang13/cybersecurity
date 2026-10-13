<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\BlockedIp;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Models\User;
use App\Services\CloudflareIpBlockService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Mockery\MockInterface;
use Tests\TestCase;

class DnsThreatMitigationStatusTest extends TestCase
{
    use RefreshDatabase;

    public function test_threat_rows_keep_cloudflare_access_rules_and_tier_three_block_lists_separate(): void
    {
        $company = Company::create([
            'name' => 'Platform Operations',
            'domain' => 'platform-status.example.test',
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
        $user = User::factory()->create([
            'company_id' => $company->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
        $cloudflareDomain = MonitoredDomain::create([
            'company_id' => $company->id,
            'domain' => 'edge.example.test',
            'infrastructure_type' => 'cloudflare',
            'is_active' => true,
            'is_owned' => true,
            'cloudflare_zone_id' => 'zone-123',
        ]);
        $tier3Domain = MonitoredDomain::create([
            'company_id' => $company->id,
            'domain' => 'app.example.test',
            'infrastructure_type' => 'app_middleware',
            'is_active' => true,
            'is_owned' => true,
        ]);
        $this->createThreat($cloudflareDomain, '203.0.113.30', 'firewallManaged', 'block', now()->subMinute());
        $this->createThreat($tier3Domain, '203.0.113.31', 'app_middleware', 'log', now());
        BlockedIp::create([
            'monitored_domain_id' => $tier3Domain->id,
            'ip' => '203.0.113.31',
            'is_global' => false,
        ]);

        $this->mock(CloudflareIpBlockService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('listAccessRules')->once()->with('zone-123')->andReturn([
                'success' => true,
                'message' => 'Access rules loaded successfully.',
                'rules' => [[
                    'id' => 'rule-123',
                    'ip_address' => '203.0.113.30',
                    'notes' => null,
                    'created_on' => null,
                ]],
            ]);
        });

        $this->actingAs($user)
            ->get(route('dns-security.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('recentThreatLogs.0.attacker_ip', '203.0.113.31')
                ->where('recentThreatLogs.0.mitigation.mechanism', 'tier3_block_list')
                ->where('recentThreatLogs.0.mitigation.status', 'active')
                ->where('recentThreatLogs.0.mitigation.can_block', false)
                ->where('recentThreatLogs.1.attacker_ip', '203.0.113.30')
                ->where('recentThreatLogs.1.source_label', 'Cloudflare WAF Managed Rules')
                ->where('recentThreatLogs.1.mitigation.mechanism', 'cloudflare_ip_access_rule')
                ->where('recentThreatLogs.1.mitigation.status', 'active')
                ->where('recentThreatLogs.1.mitigation.can_block', false));
    }

    private function createThreat(
        MonitoredDomain $domain,
        string $ipAddress,
        string $source,
        string $action,
        \DateTimeInterface $detectedAt
    ): void {
        SecurityThreatLog::create([
            'monitored_domain_id' => $domain->id,
            'attacker_ip' => $ipAddress,
            'path_targeted' => '/.env',
            'action_taken' => $action,
            'threat_source' => $source,
            'detected_at' => $detectedAt,
        ]);
    }
}
