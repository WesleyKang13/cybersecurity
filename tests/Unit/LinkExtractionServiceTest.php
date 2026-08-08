<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Services\LinkExtractionService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class LinkExtractionServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    public function test_it_extracts_links_resolves_shorteners_and_detects_anchor_mismatch(): void
    {
        Http::fake([
            'https://bit.ly/pay-now' => Http::response('', 301, [
                'Location' => 'https://evil.example/login',
            ]),
            'https://evil.example/login' => Http::response('', 200),
        ]);

        $service = new LinkExtractionService();

        $firstResult = $service->extractAndInspect(
            '<p>Please review <a href="https://bit.ly/pay-now">paypal.com</a></p>',
            'Backup link: https://bit.ly/pay-now'
        );
        $secondResult = $service->extractAndInspect(
            '<p>Please review <a href="https://bit.ly/pay-now">paypal.com</a></p>',
            ''
        );

        $this->assertCount(1, $firstResult);
        $this->assertSame($firstResult, $secondResult);
        $this->assertSame('https://bit.ly/pay-now', $firstResult[0]['url']);
        $this->assertSame('paypal.com', $firstResult[0]['anchor_text']);
        $this->assertSame('bit.ly', $firstResult[0]['domain']);
        $this->assertSame('https://evil.example/login', $firstResult[0]['resolved_url']);
        $this->assertSame('evil.example', $firstResult[0]['resolved_domain']);
        $this->assertTrue($firstResult[0]['has_text_mismatch']);
        $this->assertTrue($firstResult[0]['has_suspicious_mismatch']);
        Http::assertSentCount(2);
    }
}
