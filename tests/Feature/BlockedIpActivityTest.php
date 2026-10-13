<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\BlockedIp;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class BlockedIpActivityTest extends TestCase
{
    use RefreshDatabase;

    public function test_tier_three_block_activity_shows_only_attempts_observed_after_the_matching_block(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $user = User::factory()->create([
            'company_id' => $company->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
        $domain = $this->createDomain($company, 'protected.example.test');
        $otherDomain = $this->createDomain($company, 'other.example.test');
        $blockedAt = CarbonImmutable::parse('2026-10-13 12:00:00', 'UTC');
        $block = BlockedIp::create([
            'monitored_domain_id' => $domain->id,
            'ip' => '203.0.113.80',
            'is_global' => false,
            'reason' => 'Auto-banned: exceeded threat threshold',
        ]);
        $block->forceFill(['created_at' => $blockedAt, 'updated_at' => $blockedAt])->save();

        $this->createEvent($domain, '203.0.113.80', $blockedAt->subMinute(), '/before-block', 'log');
        $afterBlock = $this->createEvent($domain, '203.0.113.80', $blockedAt->addMinutes(2), '/after-block', 'log');
        $this->createEvent($otherDomain, '203.0.113.80', $blockedAt->addMinutes(3), '/other-domain', 'block');

        $this->actingAs($user)
            ->get(route('admin.blocked-ips.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/BlockedIpsIndex')
                ->has('blockedIps', 1)
                ->has('blockedIpActivity', 1)
                ->where('blockedIpActivity.0.blocked_ip_id', $block->id)
                ->where('blockedIpActivity.0.ip', '203.0.113.80')
                ->where('blockedIpActivity.0.attempt_count', 1)
                ->where('blockedIpActivity.0.latest_attempt.id', $afterBlock->id)
                ->where('blockedIpActivity.0.latest_attempt.action_label', 'Logged')
                ->where('blockedIpActivity.0.history.0.path_targeted', '/after-block'));
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

    private function createDomain(Company $company, string $domain): MonitoredDomain
    {
        return MonitoredDomain::create([
            'company_id' => $company->id,
            'domain' => $domain,
            'infrastructure_type' => 'app_middleware',
            'is_active' => true,
            'is_owned' => true,
        ]);
    }

    private function createEvent(
        MonitoredDomain $domain,
        string $ipAddress,
        CarbonImmutable $detectedAt,
        string $path,
        string $action
    ): SecurityThreatLog {
        return SecurityThreatLog::create([
            'monitored_domain_id' => $domain->id,
            'attacker_ip' => $ipAddress,
            'path_targeted' => $path,
            'event_type' => 'suspicious_request',
            'severity' => 'medium',
            'action_taken' => $action,
            'threat_source' => 'app_middleware',
            'detected_at' => $detectedAt,
        ]);
    }
}
