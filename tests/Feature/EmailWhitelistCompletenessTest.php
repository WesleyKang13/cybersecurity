<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\ScannedUrl;
use App\Models\User;
use App\Models\WhitelistedDomain;
use App\Services\EmailScannerService;
use App\Services\VirusTotalService;
use App\Support\GmailAuthenticationEvidence;
use App\Support\VirusTotalScanResult;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EmailWhitelistCompletenessTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.gemini.mode' => 'mock']);
        Cache::flush();
        Http::preventStrayRequests();
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);
    }

    public static function incompleteWhitelistCases(): array
    {
        return [
            'unknown URL reputation' => [
                'Review https://routine.example/document',
                'unknown',
                0,
                'url_reputation_inconclusive',
            ],
            'one vendor URL detection' => [
                'Review https://routine.example/document',
                'api_checked_flagged',
                1,
                'url_vendor_flags',
            ],
            'two vendor URL detections' => [
                'Review https://routine.example/document',
                'api_checked_flagged',
                2,
                'url_vendor_flags',
            ],
            'multiple URLs with only the first checked clean' => [
                'Review https://first.example/document and https://second.example/document',
                'cache_hit_clean',
                0,
                'multiple_urls_not_fully_verified',
            ],
            'gift card request' => [
                'Please purchase $500 gift cards and send me the codes.',
                'skipped_no_url',
                0,
                'bec_action_request',
            ],
            'bank details payment request' => [
                'Please update the vendor bank details for this payment today.',
                'skipped_no_url',
                0,
                'payment_request',
            ],
            'invoice payment request without an attachment' => [
                'Please process this invoice payment today.',
                'skipped_no_url',
                0,
                'payment_request',
            ],
            'credential and MFA request' => [
                'Send your login details and MFA code so I can verify the account.',
                'skipped_no_url',
                0,
                'credential_request',
            ],
            'secret urgent financial request' => [
                'This is urgent. Do not contact accounting; transfer funds today.',
                'skipped_no_url',
                0,
                'bec_action_request',
            ],
        ];
    }

    #[DataProvider('incompleteWhitelistCases')]
    public function test_verified_whitelist_messages_with_incomplete_checks_or_bec_requests_reach_gemini(
        string $body,
        string $outcome,
        int $votes,
        string $geminiReason
    ): void {
        $virusTotal = Mockery::mock(VirusTotalService::class);
        $hasUrl = str_contains($body, 'https://');

        if ($hasUrl) {
            $virusTotal->shouldReceive('inspectFirstUrl')
                ->once()
                ->andReturn($this->virusTotalResult($outcome, $votes));
        } else {
            $virusTotal->shouldNotReceive('inspectFirstUrl');
        }
        $scanner = new EmailScannerService($virusTotal);

        $result = $scanner->scanAndStore(User::factory()->create(), [
            'google_message_id' => 'whitelist-completeness-'.sha1($body),
            'subject' => 'Routine request',
            'sender' => 'Finance <finance@trusted.example>',
            'snippet' => $body,
            'body' => $body,
            'gmail_authentication' => $this->trustedEvidence(),
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertContains("decision:layer_2_5.virustotal={$outcome}", $result['record']->analysis_chain);
        $this->assertContains("decision:gemini_trigger={$geminiReason}", $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public function test_low_vendor_flags_are_sent_to_contextual_analysis(): void
    {
        config(['services.gemini.mode' => 'live', 'services.gemini.key' => 'test-key']);
        $prompt = null;
        Http::fake(function ($request) use (&$prompt) {
            $prompt = $request->data()['contents'][0]['parts'][0]['text'] ?? null;

            return Http::response([
                'candidates' => [[
                    'content' => ['parts' => [['text' => json_encode([
                        'risk_score' => 20,
                        'verdict' => 'SUSPICIOUS',
                        'threat_category' => 'Phishing',
                        'analysis_chain' => ['Contextual analysis ran.'],
                        'final_reasoning' => 'Low-confidence URL reputation requires review.',
                    ])]]],
                ]],
            ]);
        });
        $virusTotal = Mockery::mock(VirusTotalService::class);
        $virusTotal->shouldReceive('inspectFirstUrl')
            ->once()
            ->andReturn($this->virusTotalResult('api_checked_flagged', 2));

        $result = (new EmailScannerService($virusTotal))->scanAndStore(User::factory()->create(), [
            'google_message_id' => 'low-vendor-context',
            'subject' => 'Review request',
            'sender' => 'Finance <finance@trusted.example>',
            'snippet' => 'Review https://routine.example/document',
            'body' => 'Review https://routine.example/document',
            'gmail_authentication' => $this->trustedEvidence(),
        ]);

        $this->assertSame('Layer 3 (AI Analysis)', $result['record']->detection_layer);
        $this->assertContains('decision:layer_2_5.virustotal=api_checked_flagged', $result['record']->analysis_chain);
        $this->assertContains('decision:gemini_trigger=url_vendor_flags', $result['record']->analysis_chain);
        Http::assertSentCount(1);
        $this->assertIsString($prompt);
        $this->assertStringContainsString('"vendor_flag_count": 2', $prompt);
        $this->assertStringContainsString('"lookup_outcome": "api_checked_flagged"', $prompt);
    }

    public function test_clean_verified_whitelisted_message_without_url_attachment_or_indicator_skips_gemini(): void
    {
        $virusTotal = Mockery::mock(VirusTotalService::class);
        $virusTotal->shouldNotReceive('inspectFirstUrl');

        $result = (new EmailScannerService($virusTotal))->scanAndStore(User::factory()->create(), [
            'google_message_id' => 'clean-complete-whitelist-message',
            'subject' => 'Quarterly update',
            'sender' => 'Finance <finance@trusted.example>',
            'snippet' => 'The quarterly update is available.',
            'body' => 'The quarterly update is available.',
            'gmail_authentication' => $this->trustedEvidence(),
        ]);

        $this->assertSame('Layer 1 (Verified Whitelist)', $result['record']->detection_layer);
        $this->assertContains('decision:layer_2_5.virustotal=skipped_no_url', $result['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=skipped_verified_whitelist_clean', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    private function virusTotalResult(string $outcome, int $votes): VirusTotalScanResult
    {
        $record = new ScannedUrl([
            'url' => 'https://routine.example/document',
            'malicious_votes' => $votes,
        ]);

        return match ($outcome) {
            'cache_hit_clean', 'cache_hit_flagged' => VirusTotalScanResult::cached($record),
            'api_checked_clean', 'api_checked_flagged' => VirusTotalScanResult::apiChecked($record),
            default => VirusTotalScanResult::forStatus($outcome, 'https://routine.example/document'),
        };
    }

    private function trustedEvidence(): GmailAuthenticationEvidence
    {
        return new GmailAuthenticationEvidence(
            dmarcResult: 'pass',
            dmarcDomain: 'trusted.example',
            spfResult: 'pass',
            spfDomain: 'trusted.example',
            dkimResult: 'pass',
            dkimDomain: 'trusted.example',
        );
    }
}
