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
use Illuminate\Support\Str;
use Mockery\MockInterface;
use Tests\TestCase;

class UniversalScanLifecycleTest extends TestCase
{
    use RefreshDatabase;

    public function test_domain_creation_queues_its_initial_scan_without_running_scanners_in_the_request(): void
    {
        Queue::fake();
        [$user] = $this->platformUserAndDomain();

        $this->mock(DnsScannerService::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('scan');
        });
        $this->mock(UniversalSecurityScannerService::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('scan');
        });

        $this->actingAs($user)
            ->post(route('dns-security.store'), [
                'domain' => 'initial-queued-scan.example.test',
                'infrastructure_type' => 'universal',
            ])
            ->assertRedirect()
            ->assertSessionHas('success', "Domain 'initial-queued-scan.example.test' added. Its initial security scan has been queued.");

        $domain = MonitoredDomain::query()->where('domain', 'initial-queued-scan.example.test')->sole();
        $this->assertSame('queued', $domain->universal_scan_status);
        $this->assertNotNull($domain->universal_scan_run_id);
        Queue::assertPushed(
            RunUniversalSecurityScan::class,
            fn (RunUniversalSecurityScan $job): bool => $job->domainId === $domain->id
                && $job->scanRunId === $domain->universal_scan_run_id
        );
    }

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
        $scanRunId = (string) $domain->fresh()->universal_scan_run_id;
        $this->assertNotSame('', $scanRunId);
        Queue::assertPushed(
            RunUniversalSecurityScan::class,
            fn (RunUniversalSecurityScan $job): bool => $job->domainId === $domain->id
                && $job->companyId === $user->company_id
                && $job->scanRunId === $scanRunId
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
        $scanRunId = (string) Str::uuid();
        $domain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_run_id' => $scanRunId,
            'universal_scan_requested_at' => now(),
        ])->save();
        $job = new RunUniversalSecurityScan($domain->id, $domain->company_id, $scanRunId);

        $dnsScanner = $this->mock(DnsScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once();
        });
        $webScanner = $this->mock(UniversalSecurityScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once();
        });

        $job->handle($dnsScanner, $webScanner);

        $this->assertSame('completed', $domain->fresh()->universal_scan_status);
        $this->assertNotNull($domain->fresh()->universal_scan_completed_at);

        $domain->forceFill(['universal_scan_status' => 'running'])->save();
        $job->failed(new \RuntimeException('remote service failure'));

        $domain->refresh();
        $this->assertSame('failed', $domain->universal_scan_status);
        $this->assertSame('The scan could not complete. Please try again.', $domain->universal_scan_error);
        $this->assertNotNull($domain->universal_scan_failed_at);
    }

    public function test_stale_job_cannot_claim_or_update_a_newer_scan_run(): void
    {
        [, $domain] = $this->platformUserAndDomain();
        $currentRunId = (string) Str::uuid();
        $domain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_run_id' => $currentRunId,
            'universal_scan_requested_at' => now(),
        ])->save();

        $staleJob = new RunUniversalSecurityScan($domain->id, $domain->company_id, (string) Str::uuid());
        $dnsScanner = $this->mock(DnsScannerService::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('scan');
        });
        $webScanner = $this->mock(UniversalSecurityScannerService::class, function (MockInterface $mock): void {
            $mock->shouldNotReceive('scan');
        });

        $staleJob->handle($dnsScanner, $webScanner);
        $staleJob->failed(new \RuntimeException('stale failure'));

        $domain->refresh();
        $this->assertSame('queued', $domain->universal_scan_status);
        $this->assertSame($currentRunId, $domain->universal_scan_run_id);
    }

    public function test_legacy_queued_job_without_a_run_id_is_still_processed(): void
    {
        [, $domain] = $this->platformUserAndDomain();
        $domain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_run_id' => null,
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
    }

    public function test_scan_status_endpoint_is_company_scoped_and_returns_only_lifecycle_fields(): void
    {
        [$user, $domain] = $this->platformUserAndDomain();
        $domain->forceFill([
            'universal_scan_status' => 'running',
            'universal_scan_requested_at' => now()->subMinute(),
            'universal_scan_started_at' => now(),
        ])->save();
        $otherCompany = Company::create([
            'name' => 'Another Platform',
            'domain' => 'another-platform.example.test',
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
        $otherDomain = MonitoredDomain::create([
            'company_id' => $otherCompany->id,
            'domain' => 'other-scan-target.example.test',
            'infrastructure_type' => 'universal',
            'is_active' => true,
        ]);

        $this->actingAs($user)
            ->getJson(route('dns-security.scan-statuses', [
                'domain_ids' => [$domain->id, $otherDomain->id],
            ]))
            ->assertOk()
            ->assertJsonCount(1, 'scans')
            ->assertJsonPath('scans.0.id', $domain->id)
            ->assertJsonStructure([
                'scans' => [[
                    'id', 'status', 'requested_at', 'started_at', 'completed_at', 'failed_at', 'error',
                ]],
            ]);
    }

    public function test_recovery_command_fails_only_scans_stuck_for_more_than_thirty_minutes(): void
    {
        [, $queuedDomain] = $this->platformUserAndDomain();
        $runningDomain = MonitoredDomain::create([
            'company_id' => $queuedDomain->company_id,
            'domain' => 'running-target.example.test',
            'infrastructure_type' => 'universal',
            'is_active' => true,
        ]);
        $freshDomain = MonitoredDomain::create([
            'company_id' => $queuedDomain->company_id,
            'domain' => 'fresh-target.example.test',
            'infrastructure_type' => 'universal',
            'is_active' => true,
        ]);
        $queuedDomain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_run_id' => (string) Str::uuid(),
            'universal_scan_requested_at' => now()->subMinutes(31),
        ])->save();
        $runningDomain->forceFill([
            'universal_scan_status' => 'running',
            'universal_scan_run_id' => (string) Str::uuid(),
            'universal_scan_started_at' => now()->subMinutes(31),
        ])->save();
        $freshDomain->forceFill([
            'universal_scan_status' => 'queued',
            'universal_scan_run_id' => (string) Str::uuid(),
            'universal_scan_requested_at' => now()->subMinutes(29),
        ])->save();

        $this->artisan('app:recover-stuck-universal-scans')
            ->expectsOutput('Recovered 2 stuck universal scan(s).')
            ->assertExitCode(0);

        foreach ([$queuedDomain, $runningDomain] as $domain) {
            $domain->refresh();
            $this->assertSame('failed', $domain->universal_scan_status);
            $this->assertNull($domain->universal_scan_run_id);
            $this->assertSame('The scan timed out before it could complete. Please try again.', $domain->universal_scan_error);
        }

        $this->assertSame('queued', $freshDomain->fresh()->universal_scan_status);
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
