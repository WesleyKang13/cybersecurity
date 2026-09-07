<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Jobs\RetryEmailAnalysisJob;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Services\EmailScannerService;
use App\Services\VirusTotalService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\RateLimiter;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class GeminiAnalysisLifecycleTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config([
            'services.gemini.mode' => 'live',
            'services.gemini.key' => 'test-key',
            'services.gemini.max_analysis_attempts' => 3,
            'services.gemini.requests_per_minute' => 10,
        ]);
        RateLimiter::clear('gemini-api:provider');
        Http::preventStrayRequests();
        Queue::fake();
    }

    public function test_missing_api_key_is_failed_inconclusive_not_safe(): void
    {
        config(['services.gemini.key' => null]);

        $result = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());

        $this->assertFalse($result['record']->is_threat);
        $this->assertSame('failed', $result['record']->analysis_status);
        $this->assertSame('INCONCLUSIVE', $result['record']->verdict);
        $this->assertSame('inconclusive', $result['record']->severity);
        $this->assertSame(1, $result['record']->risk_score);
        $this->assertSame('missing_api_key', $result['record']->analysis_last_error_code);
        Queue::assertNothingPushed();
    }

    public function test_temporary_provider_failure_is_retry_pending_and_then_completes_on_the_same_row(): void
    {
        Http::fake(['generativelanguage.googleapis.com/*' => Http::sequence()
            ->push([], 503)
            ->push($this->validProviderResponse())]);
        $user = User::factory()->create();
        $first = $this->scanner()->scanAndStore($user, $this->email());

        $this->assertSame('retry_pending', $first['record']->analysis_status);
        $this->assertSame('INCONCLUSIVE', $first['record']->verdict);
        $this->assertSame('provider_5xx', $first['record']->analysis_last_error_code);
        Queue::assertPushed(RetryEmailAnalysisJob::class, fn (RetryEmailAnalysisJob $job) => $job->userId === $user->id);

        $record = $first['record']->fresh();
        $this->assertIsArray($record->analysis_retry_payload);
        $record->update(['analysis_next_retry_at' => now()->subSecond()]);
        $completed = $this->scanner()->retryIncomplete($user, $record->google_message_id);

        $this->assertSame($record->id, $completed->id);
        $this->assertSame(2, $completed->analysis_attempts);
        $this->assertSame('completed', $completed->analysis_status);
        $this->assertSame('SAFE', $completed->verdict);
        $this->assertNull($completed->analysis_retry_payload);
        $this->assertDatabaseCount('scanned_emails', 1);
    }

    public function test_invalid_provider_json_is_not_defaulted_to_safe(): void
    {
        Http::fake(['generativelanguage.googleapis.com/*' => Http::response([
            'candidates' => [['content' => ['parts' => [['text' => '{"risk_score":0}']]]]],
        ])]);

        $result = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());

        $this->assertSame('retry_pending', $result['record']->analysis_status);
        $this->assertSame('INCONCLUSIVE', $result['record']->verdict);
        $this->assertSame('invalid_schema', $result['record']->analysis_last_error_code);
    }

    public function test_permanent_bad_request_is_not_retried(): void
    {
        Http::fake(['generativelanguage.googleapis.com/*' => Http::response([], 400)]);

        $result = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());

        $this->assertSame('failed', $result['record']->analysis_status);
        $this->assertSame('invalid_request', $result['record']->analysis_last_error_code);
        Queue::assertNothingPushed();
    }

    public static function providerFailureCases(): array
    {
        return [
            'timeout response' => [408, 'timeout', 'retry_pending'],
            'provider rate limit' => [429, 'rate_limited', 'retry_pending'],
            'provider 500' => [500, 'provider_5xx', 'retry_pending'],
            'provider 502' => [502, 'provider_5xx', 'retry_pending'],
            'provider 503' => [503, 'provider_5xx', 'retry_pending'],
            'provider auth 401' => [401, 'provider_auth_error', 'failed'],
            'provider auth 403' => [403, 'provider_auth_error', 'failed'],
        ];
    }

    #[DataProvider('providerFailureCases')]
    public function test_provider_failures_are_classified_without_safe_fallback(int $httpStatus, string $code, string $state): void
    {
        Http::fake(['generativelanguage.googleapis.com/*' => Http::response([], $httpStatus)]);

        $result = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());

        $this->assertSame($state, $result['record']->analysis_status);
        $this->assertSame($code, $result['record']->analysis_last_error_code);
        $this->assertSame('INCONCLUSIVE', $result['record']->verdict);
    }

    public function test_pdf_analysis_failure_cannot_disappear_into_a_safe_result(): void
    {
        Http::fake(['generativelanguage.googleapis.com/*' => Http::response([], 500)]);

        $result = $this->scanner()->scanAndStore(User::factory()->create(), $this->email([
            'pdf_attachments' => [[
                'filename' => 'invoice.pdf',
                'mime_type' => 'application/pdf',
                'base64_data' => base64_encode('%PDF synthetic'),
            ]],
        ]));

        $this->assertSame('retry_pending', $result['record']->analysis_status);
        $this->assertSame('INCONCLUSIVE', $result['record']->verdict);
        $this->assertContains('decision:attachment_analysis=incomplete', $result['record']->analysis_chain);
    }

    public function test_retryable_failures_become_failed_after_the_bounded_attempt_limit(): void
    {
        config(['services.gemini.max_analysis_attempts' => 2]);
        Http::fake(['generativelanguage.googleapis.com/*' => Http::sequence()->push([], 503)->push([], 503)]);
        $user = User::factory()->create();
        $record = $this->scanner()->scanAndStore($user, $this->email())['record']->fresh();

        $this->scanner()->retryIncomplete($user, $record->google_message_id);

        $this->assertSame('failed', $record->fresh()->analysis_status);
        $this->assertSame('retry_exhausted', $record->fresh()->analysis_last_error_code);
        $this->assertSame('INCONCLUSIVE', $record->fresh()->verdict);
    }

    public function test_retry_lookup_is_scoped_to_its_owner(): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        Http::fake(['generativelanguage.googleapis.com/*' => Http::sequence()
            ->push([], 503)
            ->push([], 503)
            ->push($this->validProviderResponse())]);
        $a = $this->scanner()->scanAndStore($userA, $this->email(['google_message_id' => 'shared-id']))['record'];
        $b = $this->scanner()->scanAndStore($userB, $this->email(['google_message_id' => 'shared-id']))['record'];
        $a->fresh()->update(['analysis_next_retry_at' => now()->subSecond()]);
        $this->scanner()->retryIncomplete($userA, 'shared-id');

        $this->assertSame('completed', $a->fresh()->analysis_status);
        $this->assertSame('retry_pending', $b->fresh()->analysis_status);
        $this->assertSame($userB->id, $b->fresh()->user_id);
    }

    public function test_processing_lease_prevents_a_second_same_user_attempt(): void
    {
        $user = User::factory()->create();
        $record = ScannedEmail::create(array_merge($this->pendingAttributes($user), [
            'analysis_status' => 'processing',
            'analysis_lease_token' => 'active-lease',
            'analysis_lease_expires_at' => now()->addMinute(),
        ]));

        $result = $this->scanner()->scanAndStore($user, $this->email(['google_message_id' => $record->google_message_id]));

        $this->assertSame($record->id, $result['record']->id);
        Http::assertNothingSent();
    }

    public function test_global_outbound_rate_limiter_prevents_excess_provider_requests(): void
    {
        config(['services.gemini.requests_per_minute' => 1]);
        Http::fake(['generativelanguage.googleapis.com/*' => Http::response($this->validProviderResponse())]);

        $first = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());
        $second = $this->scanner()->scanAndStore(User::factory()->create(), $this->email());

        $this->assertSame('completed', $first['record']->analysis_status);
        $this->assertSame('retry_pending', $second['record']->analysis_status);
        $this->assertSame('rate_limited', $second['record']->analysis_last_error_code);
        Http::assertSentCount(1);
    }

    private function scanner(): EmailScannerService
    {
        $virusTotal = Mockery::mock(VirusTotalService::class);
        $virusTotal->shouldNotReceive('inspectFirstUrl');

        return new EmailScannerService($virusTotal);
    }

    private function email(array $overrides = []): array
    {
        return array_merge([
            'google_message_id' => 'gemini-lifecycle-'.fake()->uuid(),
            'subject' => 'Quarterly update',
            'sender' => 'sender@example.test',
            'snippet' => 'A routine update is available.',
            'body' => 'A routine update is available.',
        ], $overrides);
    }

    private function validProviderResponse(): array
    {
        return ['candidates' => [['content' => ['parts' => [['text' => json_encode([
            'risk_score' => 10,
            'verdict' => 'SAFE',
            'threat_category' => 'None',
            'analysis_chain' => ['Sender reviewed.', 'Message reviewed.', 'Technical data reviewed.'],
            'final_reasoning' => 'No suspicious indicators were found after contextual analysis.',
        ])]]]]]];
    }

    private function pendingAttributes(User $user): array
    {
        return [
            'user_id' => $user->id,
            'google_message_id' => 'processing-'.fake()->uuid(),
            'subject' => 'Pending', 'sender' => 'sender@example.test', 'snippet' => 'Pending',
            'is_threat' => false, 'detection_layer' => 'Layer 3 (Analysis Pending)',
            'severity' => 'inconclusive', 'risk_score' => 1, 'reason' => 'Analysis pending.',
            'verdict' => 'INCONCLUSIVE', 'threat_category' => 'None', 'analysis_chain' => ['Pending'],
            'final_reasoning' => 'Analysis pending.', 'analysis_retry_payload' => $this->email(),
        ];
    }
}
