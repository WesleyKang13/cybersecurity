<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Services\EmailOriginService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class EmailOriginServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    public function test_it_marks_google_workspace_as_trusted_and_caches_the_lookup(): void
    {
        Http::fake([
            'http://ip-api.com/json/*' => Http::response([
                'status' => 'success',
                'country' => 'United States',
                'city' => 'Mountain View',
                'isp' => 'Google LLC',
                'org' => 'Google LLC',
                'as' => 'AS15169',
                'asname' => 'GOOGLE',
                'proxy' => false,
                'hosting' => true,
                'query' => '209.85.220.41',
            ], 200),
        ]);

        $headers = <<<HEADERS
Received: from mail-lf1-f41.google.com (mail-lf1-f41.google.com. [209.85.220.41])
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass
HEADERS;

        $service = new EmailOriginService();

        $firstTrace = $service->trace($headers);
        $secondTrace = $service->trace($headers);

        $this->assertTrue($firstTrace['is_trusted_provider']);
        $this->assertSame('Google Workspace', $firstTrace['provider_name']);
        $this->assertFalse($firstTrace['is_proxy_or_vpn']);
        $this->assertFalse($firstTrace['is_hosting_provider']);
        $this->assertStringContainsString('Google Workspace', (string) $firstTrace['origin_note']);
        $this->assertSame($firstTrace, $secondTrace);
        Http::assertSentCount(1);
    }

    public function test_it_flags_an_untrusted_cloud_host_when_authentication_fails(): void
    {
        Http::fake([
            'http://ip-api.com/json/*' => Http::response([
                'status' => 'success',
                'country' => 'United States',
                'city' => 'Ashburn',
                'isp' => 'Amazon.com, Inc.',
                'org' => 'Amazon.com, Inc.',
                'as' => 'AS14618',
                'asname' => 'AMAZON-AES',
                'proxy' => false,
                'hosting' => true,
                'query' => '54.240.8.44',
            ], 200),
        ]);

        $headers = <<<HEADERS
Received: from ec2-54-240-8-44.compute-1.amazonaws.com (ec2-54-240-8-44.compute-1.amazonaws.com. [54.240.8.44])
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example.com; dkim=fail header.i=@example.com; dmarc=fail
HEADERS;

        $trace = (new EmailOriginService())->trace($headers);

        $this->assertFalse($trace['is_trusted_provider']);
        $this->assertTrue($trace['is_hosting_provider']);
        $this->assertTrue($trace['is_hosting_provider_warning']);
        $this->assertFalse($trace['is_proxy_or_vpn']);
    }
}
