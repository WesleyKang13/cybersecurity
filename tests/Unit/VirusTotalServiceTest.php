<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Models\ScannedUrl;
use App\Services\VirusTotalService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

class VirusTotalServiceTest extends TestCase
{
    use RefreshDatabase;

    private string|false $originalApiKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalApiKey = getenv('VIRUSTOTAL_API_KEY');
        putenv('VIRUSTOTAL_API_KEY=test-key');
        config(['services.gemini.mode' => 'live']);
        Http::preventStrayRequests();
    }

    protected function tearDown(): void
    {
        $this->originalApiKey === false
            ? putenv('VIRUSTOTAL_API_KEY')
            : putenv("VIRUSTOTAL_API_KEY={$this->originalApiKey}");

        parent::tearDown();
    }

    public function test_no_url_is_explicitly_skipped_without_a_lookup(): void
    {
        $result = $this->service()->inspectFirstUrl([]);

        $this->assertSame('skipped_no_url', $result->status);
        Http::assertNothingSent();
    }

    public function test_cached_clean_and_flagged_results_remain_distinguishable(): void
    {
        ScannedUrl::create(['url' => 'https://clean.example/path', 'is_malicious' => false, 'malicious_votes' => 0]);
        ScannedUrl::create(['url' => 'https://flagged.example/path', 'is_malicious' => true, 'malicious_votes' => 2]);

        $clean = $this->service()->inspectFirstUrl(['https://clean.example/path']);
        $flagged = $this->service()->inspectFirstUrl(['https://flagged.example/path']);

        $this->assertSame('cache_hit_clean', $clean->status);
        $this->assertSame('cache_hit_flagged', $flagged->status);
        $this->assertSame(2, $flagged->vendorFlagCount());
        Http::assertNothingSent();
    }

    public static function providerOutcomeCases(): array
    {
        return [
            'clean API report' => [200, 0, 'api_checked_clean'],
            'flagged API report' => [200, 2, 'api_checked_flagged'],
            'unknown report' => [404, null, 'unknown'],
            'rate-limited request' => [429, null, 'rate_limited'],
            'unavailable provider' => [500, null, 'unavailable'],
        ];
    }

    #[DataProvider('providerOutcomeCases')]
    public function test_provider_outcomes_are_not_collapsed_into_clean(
        int $status,
        ?int $vendorVotes,
        string $expectedOutcome
    ): void {
        Http::fake([
            'virustotal.com/*' => Http::response(
                $vendorVotes === null ? [] : [
                    'data' => [
                        'attributes' => [
                            'last_analysis_stats' => ['malicious' => $vendorVotes, 'suspicious' => 0],
                            'last_analysis_results' => $vendorVotes > 0
                                ? ['Synthetic Vendor' => ['category' => 'malicious']]
                                : [],
                        ],
                    ],
                ],
                $status
            ),
        ]);

        $result = $this->service()->inspectFirstUrl(['https://new.example/path']);

        $this->assertSame($expectedOutcome, $result->status);
        $this->assertSame($vendorVotes ?? 0, $result->vendorFlagCount());
        Http::assertSentCount(1);
    }

    public function test_provider_exception_is_explicitly_failed(): void
    {
        Http::fake(fn () => throw new RuntimeException('Synthetic network failure'));

        $result = $this->service()->inspectFirstUrl(['https://new.example/path']);

        $this->assertSame('failed', $result->status);
    }

    private function service(): VirusTotalService
    {
        return new class extends VirusTotalService
        {
            protected function throttleForRateLimit(): void
            {
                // The production 15-second quota delay is not needed for HTTP fakes.
            }
        };
    }
}
