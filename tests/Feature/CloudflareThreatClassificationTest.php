<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Services\CloudflareThreatService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class CloudflareThreatClassificationTest extends TestCase
{
    use RefreshDatabase;

    public function test_cloudflare_sync_classifies_recognizable_paths_but_preserves_raw_source_and_action(): void
    {
        config(['services.cloudflare.api_token' => 'test-token']);
        $company = Company::create([
            'name' => 'Cloudflare Client',
            'domain' => 'cloudflare-client.example.test',
            'type' => Company::TYPE_CLIENT,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
        $domain = MonitoredDomain::create([
            'company_id' => $company->id,
            'domain' => 'edge.example.test',
            'infrastructure_type' => 'cloudflare',
            'is_active' => true,
            'is_owned' => true,
            'cloudflare_zone_id' => 'zone-123',
        ]);

        Http::fake([
            'https://api.cloudflare.com/client/v4/graphql' => Http::response([
                'data' => [
                    'viewer' => [
                        'zones' => [[
                            'firewallEventsAdaptive' => [[
                                'clientIP' => '203.0.113.90',
                                'clientCountryName' => 'United Kingdom',
                                'clientRequestPath' => '/.env',
                                'action' => 'block',
                                'source' => 'firewallManaged',
                                'datetime' => '2026-10-13T12:00:00Z',
                            ]],
                        ]],
                    ],
                ],
            ]),
        ]);
        app(CloudflareThreatService::class)->syncOwnedDomains();

        $event = SecurityThreatLog::query()->sole();
        $this->assertSame($domain->id, $event->monitored_domain_id);
        $this->assertSame('environment_file_probe', $event->event_type);
        $this->assertSame('high', $event->severity);
        $this->assertSame('Attempted request for a sensitive environment configuration path.', $event->reason);
        $this->assertSame('block', $event->action_taken);
        $this->assertSame('firewallManaged', $event->threat_source);
    }
}
