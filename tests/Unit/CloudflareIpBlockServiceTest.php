<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Services\CloudflareIpBlockService;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class CloudflareIpBlockServiceTest extends TestCase
{
    public function test_access_rule_lookup_reads_each_cloudflare_page_before_reporting_status(): void
    {
        config(['services.cloudflare.api_token' => 'test-token']);

        Http::fake(function (Request $request) {
            parse_str((string) parse_url($request->url(), PHP_URL_QUERY), $query);
            $page = (int) ($query['page'] ?? 1);

            return Http::response([
                'success' => true,
                'result' => [[
                    'id' => "rule-{$page}",
                    'configuration' => ['value' => "203.0.113.{$page}"],
                    'notes' => null,
                    'created_on' => null,
                ]],
                'result_info' => ['total_pages' => 2],
            ]);
        });

        $result = app(CloudflareIpBlockService::class)->listAccessRules('zone-123');

        $this->assertTrue($result['success']);
        $this->assertSame(['203.0.113.1', '203.0.113.2'], array_column($result['rules'], 'ip_address'));
        Http::assertSentCount(2);
    }
}
