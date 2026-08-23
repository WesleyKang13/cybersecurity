<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\BlockedIp;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class Tier3ThreatTelemetryTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    public function test_legacy_telemetry_payload_without_enrichment_still_succeeds(): void
    {
        $domain = $this->createTier3Domain();

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', [
                'threats' => [$this->legacyEvent()],
            ])
            ->assertAccepted()
            ->assertJson([
                'success' => true,
                'events_received' => 1,
                'events_synced' => 1,
                'new_events_count' => 1,
            ]);

        $log = SecurityThreatLog::query()->sole();

        $this->assertSame('198.51.100.10', $log->attacker_ip);
        $this->assertSame('/legacy-probe', $log->path_targeted);
        $this->assertSame('Legacy Client/1.0', $log->user_agent);
        $this->assertNull($log->event_type);
        $this->assertNull($log->severity);
        $this->assertNull($log->reason);
        $this->assertNull($log->metadata);
        $this->assertSame('log', $log->action_taken);
    }

    public function test_enriched_telemetry_is_stored_while_action_remains_separate(): void
    {
        $domain = $this->createTier3Domain();
        $event = array_merge($this->legacyEvent(), [
            'targeted_path' => '/login',
            'event_type' => 'failed_login',
            'severity' => 'medium',
            'reason' => 'Authentication failed',
            'metadata' => [
                'route_name' => 'login',
                'http_method' => 'POST',
                'attempt_count' => 1,
            ],
        ]);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertAccepted();

        $log = SecurityThreatLog::query()->sole();

        $this->assertSame('failed_login', $log->event_type);
        $this->assertSame('medium', $log->severity);
        $this->assertSame('Authentication failed', $log->reason);
        $this->assertSame([
            'route_name' => 'login',
            'http_method' => 'POST',
            'attempt_count' => 1,
        ], $log->metadata);
        $this->assertSame('log', $log->action_taken);
    }

    public function test_legacy_retry_does_not_erase_existing_enrichment(): void
    {
        $domain = $this->createTier3Domain();
        $legacyEvent = $this->legacyEvent();
        $enrichedEvent = array_merge($legacyEvent, [
            'event_type' => 'suspicious_request',
            'severity' => 'low',
            'reason' => 'Matched a sanitized request signature',
            'metadata' => ['matched_pattern' => 'legacy-probe'],
        ]);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$enrichedEvent]])
            ->assertAccepted();

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$legacyEvent]])
            ->assertAccepted();

        $log = SecurityThreatLog::query()->sole();

        $this->assertSame('suspicious_request', $log->event_type);
        $this->assertSame('low', $log->severity);
        $this->assertSame('Matched a sanitized request signature', $log->reason);
        $this->assertSame(['matched_pattern' => 'legacy-probe'], $log->metadata);
    }

    public function test_existing_legacy_records_remain_readable(): void
    {
        $domain = $this->createTier3Domain();

        $record = SecurityThreatLog::create([
            'monitored_domain_id' => $domain->id,
            'attacker_ip' => '203.0.113.20',
            'path_targeted' => '/old-event',
            'user_agent' => 'Historical Client',
            'action_taken' => 'log',
            'threat_source' => 'app_middleware',
            'detected_at' => now()->subDay(),
        ]);

        $record = SecurityThreatLog::query()->findOrFail($record->id);

        $this->assertSame('/old-event', $record->path_targeted);
        $this->assertSame('log', $record->action_taken);
        $this->assertNull($record->event_type);
        $this->assertNull($record->severity);
        $this->assertNull($record->reason);
        $this->assertNull($record->metadata);
    }

    public function test_invalid_severity_is_rejected(): void
    {
        $domain = $this->createTier3Domain();
        $event = array_merge($this->legacyEvent(), ['severity' => 'urgent']);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('threats.0.severity');

        $this->assertDatabaseCount('security_threat_logs', 0);
    }

    public function test_oversized_or_invalid_optional_fields_are_rejected(): void
    {
        $domain = $this->createTier3Domain();
        $invalidValues = [
            'event_type' => str_repeat('a', 101),
            'reason' => str_repeat('r', 2001),
            'metadata' => ['safe_context' => str_repeat('m', 17000)],
        ];

        foreach ($invalidValues as $field => $value) {
            $event = array_merge($this->legacyEvent(), [$field => $value]);

            $this->withToken((string) $domain->app_secret_token)
                ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
                ->assertUnprocessable()
                ->assertJsonValidationErrors("threats.0.{$field}");
        }

        $event = array_merge($this->legacyEvent(), ['metadata' => 'not-structured-json']);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('threats.0.metadata');

        $this->assertDatabaseCount('security_threat_logs', 0);
    }

    public function test_event_batches_and_total_request_size_are_bounded(): void
    {
        $domain = $this->createTier3Domain();

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', [
                'threats' => array_fill(0, 101, $this->legacyEvent()),
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('threats');

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', [
                'threats' => [$this->legacyEvent()],
                'ignored_padding' => str_repeat('x', 525000),
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('payload');

        $this->assertDatabaseCount('security_threat_logs', 0);
    }

    public function test_sensitive_metadata_keys_are_rejected_and_request_body_is_not_captured(): void
    {
        $domain = $this->createTier3Domain();
        $event = array_merge($this->legacyEvent(), [
            'metadata' => [
                'request_body' => ['email' => 'person@example.test', 'password' => 'secret'],
            ],
        ]);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('threats.0.metadata');

        $event['metadata'] = ['authorization_headers' => ['Bearer must-not-be-stored']];

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('threats.0.metadata');

        unset($event['metadata']);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event], 'unrelated_body_value' => 'not metadata'])
            ->assertAccepted();

        $this->assertNull(SecurityThreatLog::query()->sole()->metadata);
    }

    public function test_telemetry_requires_the_valid_application_secret_with_or_without_enrichment(): void
    {
        $domain = $this->createTier3Domain();
        $event = array_merge($this->legacyEvent(), [
            'event_type' => 'failed_login',
            'severity' => 'medium',
            'reason' => 'Authentication failed',
        ]);

        $this->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnauthorized();

        $this->withToken('invalid-app-secret')
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertUnauthorized();

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
            ->assertAccepted();

        $this->assertDatabaseCount('security_threat_logs', 1);
    }

    public function test_existing_auto_ban_threshold_behavior_is_unchanged_by_severity(): void
    {
        $domain = $this->createTier3Domain(['auto_ban_threshold' => 2]);

        foreach (range(1, 2) as $sequence) {
            $event = array_merge($this->legacyEvent(), [
                'timestamp' => now()->addSeconds($sequence)->toIso8601String(),
                'severity' => 'critical',
            ]);

            $this->withToken((string) $domain->app_secret_token)
                ->postJson('/api/v1/telemetry/threats', ['threats' => [$event]])
                ->assertAccepted();
        }

        $this->assertDatabaseCount('blocked_ips', 0);

        $thirdEvent = array_merge($this->legacyEvent(), [
            'timestamp' => now()->addSeconds(3)->toIso8601String(),
            'severity' => 'info',
        ]);

        $this->withToken((string) $domain->app_secret_token)
            ->postJson('/api/v1/telemetry/threats', ['threats' => [$thirdEvent]])
            ->assertAccepted();

        $this->assertDatabaseHas('blocked_ips', [
            'ip' => '198.51.100.10',
            'is_global' => true,
            'reason' => 'Auto-banned: exceeded threat threshold',
        ]);
    }

    public function test_blocked_ip_polling_response_is_unchanged(): void
    {
        $domain = $this->createTier3Domain();
        $otherDomain = $this->createTier3Domain(['domain' => 'other.example.test']);

        BlockedIp::create(['ip' => '192.0.2.1', 'is_global' => true, 'reason' => 'Global test block']);
        BlockedIp::create([
            'monitored_domain_id' => $domain->id,
            'ip' => '192.0.2.2',
            'is_global' => false,
            'reason' => 'Domain test block',
        ]);
        BlockedIp::create([
            'monitored_domain_id' => $otherDomain->id,
            'ip' => '192.0.2.3',
            'is_global' => false,
            'reason' => 'Other domain test block',
        ]);

        $this->withToken((string) $domain->app_secret_token)
            ->getJson('/api/v1/telemetry/blocked-ips')
            ->assertOk()
            ->assertExactJson(['192.0.2.1', '192.0.2.2']);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function createTier3Domain(array $overrides = []): MonitoredDomain
    {
        return MonitoredDomain::create(array_merge([
            'domain' => 'protected.example.test',
            'infrastructure_type' => 'app_middleware',
            'is_active' => true,
            'is_owned' => true,
            'auto_ban_threshold' => 10,
        ], $overrides));
    }

    /**
     * @return array<string, string>
     */
    private function legacyEvent(): array
    {
        return [
            'attacker_ip' => '198.51.100.10',
            'targeted_path' => '/legacy-probe',
            'user_agent' => 'Legacy Client/1.0',
            'timestamp' => '2026-08-22T12:00:00+00:00',
        ];
    }
}
