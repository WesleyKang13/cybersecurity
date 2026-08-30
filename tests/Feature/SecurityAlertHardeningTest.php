<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Models\User;
use App\Notifications\SecurityAlertNotification;
use App\Services\AttackSpikeAlertService;
use App\Services\DnsScannerService;
use App\Services\SecurityAlertDispatcher;
use App\Services\UniversalSecurityScannerService;
use App\Support\AlertTimestampFormatter;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class SecurityAlertHardeningTest extends TestCase
{
    use RefreshDatabase;

    private CarbonImmutable $now;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        Notification::fake();

        $this->now = CarbonImmutable::parse('2026-08-30 00:00:00', 'UTC');
        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        config([
            'security.alerts.timezone' => 'Europe/Dublin',
            'security.alerts.attack_spike.window_minutes' => 10,
            'security.alerts.attack_spike.high_threshold' => 10,
            'security.alerts.attack_spike.critical_threshold' => 25,
        ]);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    public function test_dispatcher_delivers_only_to_enabled_users_in_the_alert_company(): void
    {
        $companyA = $this->createCompany(Company::TYPE_CLIENT);
        $companyB = $this->createCompany(Company::TYPE_CLIENT);
        $enabledCompanyAUser = $this->createAlertUser($companyA, User::ROLE_CLIENT_ADMIN);
        $disabledCompanyAUser = $this->createAlertUser(
            $companyA,
            User::ROLE_CLIENT_USER,
            emailEnabled: false
        );
        $enabledCompanyBUser = $this->createAlertUser($companyB, User::ROLE_CLIENT_ADMIN);

        app(SecurityAlertDispatcher::class)->dispatch(
            $companyA,
            $this->genericNotification()
        );

        Notification::assertSentTo($enabledCompanyAUser, SecurityAlertNotification::class);
        Notification::assertNotSentTo($disabledCompanyAUser, SecurityAlertNotification::class);
        Notification::assertNotSentTo($enabledCompanyBUser, SecurityAlertNotification::class);
    }

    public function test_platform_domain_alert_reaches_an_enabled_platform_user(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $platformUser = $this->createAlertUser($platformCompany, User::ROLE_PLATFORM_STAFF);
        $domain = $this->createDomain($platformCompany, 'platform.example.test');

        app(SecurityAlertDispatcher::class)->dispatch(
            $domain->company,
            $this->genericNotification($domain->domain)
        );

        Notification::assertSentTo($platformUser, SecurityAlertNotification::class);
    }

    public function test_new_platform_managed_domain_persists_the_platform_company_owner(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $platformUser = $this->createAlertUser($platformCompany, User::ROLE_PLATFORM_OWNER);

        $this->mock(DnsScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once()->andReturn([
                'vulnerability_count' => 0,
            ]);
        });
        $this->mock(UniversalSecurityScannerService::class, function (MockInterface $mock): void {
            $mock->shouldReceive('scan')->once()->andReturn([
                'scan' => (object) ['security_score' => 100],
            ]);
        });

        $this->actingAs($platformUser)
            ->post(route('dns-security.store'), [
                'domain' => 'owned.example.test',
                'infrastructure_type' => 'universal',
                'cloudflare_zone_id' => '',
            ])
            ->assertRedirect()
            ->assertSessionHasNoErrors();

        $domain = MonitoredDomain::query()->where('domain', 'owned.example.test')->sole();

        $this->assertSame($platformCompany->id, $domain->company_id);
        $this->assertTrue($domain->company->is($platformCompany));
        $this->assertTrue($platformCompany->fresh()->monitoredDomains->contains($domain));
    }

    public function test_domain_ownership_migration_backfills_existing_domains_to_the_platform_company(): void
    {
        $migration = require database_path(
            'migrations/2026_08_30_120000_add_company_id_to_monitored_domains_table.php'
        );
        $migration->down();

        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $domainId = DB::table('monitored_domains')->insertGetId([
            'domain' => 'legacy-platform.example.test',
            'infrastructure_type' => 'universal',
            'is_active' => true,
            'created_at' => $this->now,
            'updated_at' => $this->now,
        ]);

        $migration->up();

        $this->assertDatabaseHas('monitored_domains', [
            'id' => $domainId,
            'company_id' => $platformCompany->id,
        ]);
    }

    #[DataProvider('attackSpikeThresholdCases')]
    public function test_attack_spike_thresholds(int $eventCount, ?string $expectedSeverity): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $user = $this->createAlertUser($company, User::ROLE_CLIENT_ADMIN);
        $domain = $this->createDomain($company, "threshold-{$eventCount}.example.test");
        $this->createThreatEvents($domain, $eventCount, $this->now->subMinutes(5));

        app(AttackSpikeAlertService::class)->evaluate($domain, $eventCount);

        if ($expectedSeverity === null) {
            Notification::assertNotSentTo($user, SecurityAlertNotification::class);

            return;
        }

        Notification::assertSentTo(
            $user,
            SecurityAlertNotification::class,
            fn (SecurityAlertNotification $notification): bool => $notification->alertType === 'attack_spike'
                && $notification->severity === $expectedSeverity
                && $notification->details['events_in_window'] === $eventCount
        );
    }

    /**
     * @return array<string, array{int, string|null}>
     */
    public static function attackSpikeThresholdCases(): array
    {
        return [
            'nine events do not alert' => [9, null],
            'ten events are high' => [10, 'HIGH'],
            'twenty-four events are high' => [24, 'HIGH'],
            'twenty-five events are critical' => [25, 'CRITICAL'],
        ];
    }

    public function test_attack_spike_counts_only_persisted_event_timestamps_inside_the_window(): void
    {
        config([
            'security.alerts.attack_spike.high_threshold' => 2,
            'security.alerts.attack_spike.critical_threshold' => 3,
        ]);

        $company = $this->createCompany(Company::TYPE_CLIENT);
        $user = $this->createAlertUser($company, User::ROLE_CLIENT_ADMIN);
        $domain = $this->createDomain($company, 'window.example.test');

        $this->createThreatEvents($domain, 1, $this->now->subMinutes(11), 1);
        $this->createThreatEvents($domain, 2, $this->now->subMinutes(9), 10);
        $this->createThreatEvents($domain, 1, $this->now->addMinute(), 20);

        app(AttackSpikeAlertService::class)->evaluate($domain, 99);

        Notification::assertSentTo(
            $user,
            SecurityAlertNotification::class,
            fn (SecurityAlertNotification $notification): bool => $notification->severity === 'HIGH'
                && $notification->details['events_in_window'] === 2
                && $notification->details['monitoring_window_minutes'] === 10
                && $notification->details['new_events_added_during_latest_sync'] === 99
        );
    }

    public function test_attack_spike_notification_has_clear_type_counts_and_local_timestamp(): void
    {
        $notification = new SecurityAlertNotification(
            alertType: 'attack_spike',
            domainName: 'wesleyk.cloud',
            severity: 'HIGH',
            message: '12 security events were detected during the last 10 minutes.',
            detectedAt: $this->now,
            details: [
                'events_in_window' => 12,
                'monitoring_window_minutes' => 10,
                'high_threshold' => 10,
                'critical_threshold' => 25,
                'new_events_added_during_latest_sync' => 10,
            ]
        );
        $text = $notification->toMarkdownText();
        $mail = $notification->toMail(new \stdClass);

        $this->assertSame('Attack Spike Alert', $notification->heading());
        $this->assertSame('[HIGH] Attack Spike Detected - wesleyk.cloud', $notification->subjectLine());
        $this->assertSame('Attack Spike Alert', $mail->greeting);
        $this->assertContains('Detected: 30 Aug 2026, 1:00 AM', $mail->introLines);
        $this->assertContains('Timezone: Europe/Dublin', $mail->introLines);
        $this->assertContains('12 security events were detected during the last 10 minutes.', $mail->introLines);
        $this->assertStringContainsString('**Severity:** HIGH', $text);
        $this->assertStringContainsString('**Domain:** wesleyk.cloud', $text);
        $this->assertStringContainsString('**Detected:** 30 Aug 2026, 1:00 AM', $text);
        $this->assertStringContainsString('**Timezone:** Europe/Dublin', $text);
        $this->assertStringContainsString('12 security events were detected during the last 10 minutes.', $text);
        $this->assertStringContainsString('HIGH threshold: 10 events', $text);
        $this->assertStringContainsString('CRITICAL threshold: 25 events', $text);
        $this->assertStringContainsString('New events added during latest sync: 10', $text);
        $this->assertStringNotContainsString('DNS Security Alert', $text);
    }

    public function test_alert_timestamp_formatter_handles_dublin_daylight_saving_time(): void
    {
        $formatter = app(AlertTimestampFormatter::class);

        $this->assertSame(
            '30 Aug 2026, 1:00 AM',
            $formatter->format(CarbonImmutable::parse('2026-08-30 00:00:00', 'UTC'))
        );
        $this->assertSame(
            '30 Dec 2026, 12:00 AM',
            $formatter->format(CarbonImmutable::parse('2026-12-30 00:00:00', 'UTC'))
        );
        $this->assertSame('Europe/Dublin', $formatter->timezone());
    }

    public function test_dns_and_ssl_notifications_keep_type_specific_headings_and_subjects(): void
    {
        $dns = new SecurityAlertNotification('dns_drift', 'example.com', 'CRITICAL', 'DNS changed.');
        $ssl = new SecurityAlertNotification('ssl_warning', 'example.com', 'WARNING', 'Certificate expires.');

        $this->assertSame('DNS Drift Alert', $dns->heading());
        $this->assertSame('[CRITICAL] DNS Drift Detected - example.com', $dns->subjectLine());
        $this->assertSame('SSL Certificate Alert', $ssl->heading());
        $this->assertSame('[WARNING] SSL Certificate Expiry - example.com', $ssl->subjectLine());
    }

    public function test_attack_spike_cooldowns_are_isolated_by_company_and_domain(): void
    {
        $companyA = $this->createCompany(Company::TYPE_CLIENT);
        $companyB = $this->createCompany(Company::TYPE_CLIENT);
        $userA = $this->createAlertUser($companyA, User::ROLE_CLIENT_ADMIN);
        $userB = $this->createAlertUser($companyB, User::ROLE_CLIENT_ADMIN);
        $domainA = $this->createDomain($companyA, 'company-a.example.test');
        $domainB = $this->createDomain($companyB, 'company-b.example.test');
        $this->createThreatEvents($domainA, 10, $this->now->subMinutes(5), 1);
        $this->createThreatEvents($domainB, 10, $this->now->subMinutes(5), 50);

        $service = app(AttackSpikeAlertService::class);
        $service->evaluate($domainA, 10);
        $service->evaluate($domainB, 10);

        Notification::assertSentTo($userA, SecurityAlertNotification::class);
        Notification::assertSentTo($userB, SecurityAlertNotification::class);
        $this->assertTrue(Cache::has("security_alert:attack_spike:{$companyA->id}:{$domainA->id}"));
        $this->assertTrue(Cache::has("security_alert:attack_spike:{$companyB->id}:{$domainB->id}"));
    }

    private function genericNotification(string $domain = 'example.test'): SecurityAlertNotification
    {
        return new SecurityAlertNotification(
            alertType: 'dns_drift',
            domainName: $domain,
            severity: 'HIGH',
            message: 'A DNS security regression was detected.',
            detectedAt: $this->now
        );
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

    private function createAlertUser(
        Company $company,
        string $role,
        bool $emailEnabled = true
    ): User {
        return User::factory()->create([
            'company_id' => $company->id,
            'role' => $role,
            'security_alert_email_enabled' => $emailEnabled,
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

    private function createThreatEvents(
        MonitoredDomain $domain,
        int $count,
        CarbonImmutable $detectedAt,
        int $ipOffset = 1
    ): void {
        foreach (range(0, $count - 1) as $index) {
            SecurityThreatLog::create([
                'monitored_domain_id' => $domain->id,
                'attacker_ip' => '198.51.100.'.($ipOffset + $index),
                'path_targeted' => "/probe/{$index}",
                'event_type' => 'suspicious_request',
                'severity' => 'medium',
                'action_taken' => 'log',
                'threat_source' => 'app_middleware',
                'detected_at' => $detectedAt->addSeconds($index),
            ]);
        }
    }
}
