<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Jobs\RunUniversalSecurityScan;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\User;
use App\Services\DnsScannerService;
use App\Services\UniversalSecurityScannerService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Mockery\MockInterface;
use Tests\TestCase;

class UniversalScanLifecycleTest extends TestCase
{
    use RefreshDatabase;

    public function test_scan_now_queues_one_company_scoped_job_and_returns_without_running_the_scan(): void
    {
        Queue::fake();
        [$user, $domain] = $this->platformUserAndDomain();

        $this->actingAs($user)
            ->post(route('dns-security.scan', $domain))
            ->assertRedirect()
            ->assertSessionHas('success', "Security scan queued for '{$domain->domain}'.");

        $this->assertDatabaseHas('monitored_domains', [
            'id' => $domain->id,
            'company_id' => $user->company_id,
            'universal_scan_status' => 'queued',
        ]);
        Queue::assertPushed(
            RunUniversalSecurityScan::class,
            fn (RunUniversalSecurityScan $job): bool => $job->domainId === $domain->id
                && $job->companyId === $user->company_id
        );

        $this->actingAs($user)
            ->post(route('dns-security.scan', $domain))
            ->assertRedirect()
            ->assertSessionHas('success', "A security scan for '{$domain->domain}' is already in progress.");

        Queue::assertPushed(RunUniversalSecurityScan::class, 1);
    }

    public function test_queued_scan_records_completion_or_a_safe_failure_state(): void
    {
        [, $domain] = $this->platformUserAndDomain();
        $domain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_requested_at' => now(),
        ])->save();
        $job = new RunUniversalSecurityScan($domain->id, $domain->company_id);

        $dnsScanner = $this->mock(DnsScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once();
        });
        $webScanner = $this->mock(UniversalSecurityScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once();
        });

        $job->handle($dnsScanner, $webScanner);

        $this->assertSame('completed', $domain->fresh()->universal_scan_status);
        $this->assertNotNull($domain->fresh()->universal_scan_completed_at);

        $job->failed(new \RuntimeException('remote service failure'));

        $domain->refresh();
        $this->assertSame('failed', $domain->universal_scan_status);
        $this->assertSame('The scan could not complete. Please try again.', $domain->universal_scan_error);
        $this->assertNotNull($domain->universal_scan_failed_at);
    }

    /**
     * @return array{User, MonitoredDomain}
     */
    private function platformUserAndDomain(): array
    {
        $company = Company::create([
            'name' => 'Platform Operations',
            'domain' => 'platform-operations.example.test',
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
            'domain' => 'scan-target.example.test',
            'infrastructure_type' => 'universal',
            'is_active' => true,
        ]);

        return [$user, $domain];
    }
}
