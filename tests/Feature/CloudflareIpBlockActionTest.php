<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\User;
use App\Services\CloudflareIpBlockService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Mockery\MockInterface;
use Tests\TestCase;

class CloudflareIpBlockActionTest extends TestCase
{
    use RefreshDatabase;

    public function test_existing_cloudflare_access_rule_is_reported_without_another_block_request(): void
    {
        [$user, $domain] = $this->platformUserAndCloudflareDomain();

        $this->mock(CloudflareIpBlockService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('listAccessRules')->once()->with('zone-123')->andReturn([
                'success' => true,
                'message' => 'Access rules loaded successfully.',
                'rules' => [[
                    'id' => 'rule-123',
                    'ip_address' => '203.0.113.50',
                    'notes' => null,
                    'created_on' => null,
                ]],
            ]);
            $mock->shouldNotReceive('blockIp');
        });

        $this->actingAs($user)
            ->post(route('dns-security.block-ip'), [
                'domain_id' => $domain->id,
                'ip_address' => '203.0.113.50',
            ])
            ->assertRedirect()
            ->assertSessionHas('success', "203.0.113.50 is already blocked by a Cloudflare IP Access Rule for '{$domain->domain}'.");
    }

    public function test_concurrent_cloudflare_block_request_is_rejected_before_any_external_call(): void
    {
        [$user, $domain] = $this->platformUserAndCloudflareDomain();
        $ipAddress = '203.0.113.51';
        $lockKey = 'cloudflare_ip_block_request:'.hash('sha256', "{$domain->cloudflare_zone_id}|{$ipAddress}");
        Cache::put($lockKey, 'another-request', now()->addSeconds(20));

        $this->mock(CloudflareIpBlockService::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('listAccessRules');
            $mock->shouldNotReceive('blockIp');
        });

        $this->actingAs($user)
            ->post(route('dns-security.block-ip'), [
                'domain_id' => $domain->id,
                'ip_address' => $ipAddress,
            ])
            ->assertSessionHasErrors('block_ip');
    }

    /**
     * @return array{User, MonitoredDomain}
     */
    private function platformUserAndCloudflareDomain(): array
    {
        $company = Company::create([
            'name' => 'Platform Operations',
            'domain' => 'platform-cf.example.test',
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
        $user = User::factory()->create([
            'company_id' => $company->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
        $domain = MonitoredDomain::create([
            'company_id' => $company->id,
            'domain' => 'edge.example.test',
            'infrastructure_type' => 'cloudflare',
            'is_active' => true,
            'is_owned' => true,
            'cloudflare_zone_id' => 'zone-123',
        ]);

        return [$user, $domain];
    }
}
