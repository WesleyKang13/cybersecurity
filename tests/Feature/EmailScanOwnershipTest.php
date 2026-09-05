<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Services\EmailScannerService;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EmailScanOwnershipTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        ScannedEmail::flushEventListeners();

        parent::tearDown();
    }

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.gemini.mode' => 'mock']);
        Cache::flush();
        Http::preventStrayRequests();
        Http::fake();
    }

    public static function ownershipCases(): array
    {
        return [
            'different companies, active' => [false, false],
            'same company, active' => [true, false],
            'different companies, deleted' => [false, true],
            'same company, deleted' => [true, true],
        ];
    }

    #[DataProvider('ownershipCases')]
    public function test_authenticated_scan_isolates_another_users_message(bool $sameCompany, bool $deleted): void
    {
        $companyA = Company::create(['name' => 'Synthetic company A']);
        $companyB = $sameCompany ? $companyA : Company::create(['name' => 'Synthetic company B']);
        $userA = User::factory()->create(['company_id' => $companyA->id]);
        $userB = User::factory()->create(['company_id' => $companyB->id]);
        $scanner = app(EmailScannerService::class);
        $original = $scanner->scanAndStore($userA, $this->email([
            'subject' => 'Private subject A',
            'sender' => 'private@synthetic-a.xyz',
            'snippet' => 'Private snippet A',
        ]))['record'];

        if ($deleted) {
            $original->delete();
        }

        $originalAttributes = $original->fresh()->getRawOriginal();
        $submitted = $this->email([
            'user_id' => $userA->id,
            'company_id' => $companyA->id,
        ]);

        $response = $this->actingAs($userB)->postJson('/api/scan-email', [
            'user_id' => $userA->id,
            'company_id' => $companyA->id,
            'emails' => [$submitted],
        ])->assertOk();

        // This assertion exposes the original leak before the service/schema fix.
        $response->assertJsonPath('results.0.subject', $submitted['subject'])
            ->assertJsonPath('results.0.sender', $submitted['sender'])
            ->assertJsonPath('results.0.snippet', $submitted['snippet'])
            ->assertJsonPath('results.0.created', true)
            ->assertJsonPath('results.0.verdict', 'SAFE')
            ->assertJsonPath('results.0.detection_layer', 'Layer 3 (Mock AI)');

        $owned = ScannedEmail::withTrashed()->findOrFail($response->json('results.0.id'));
        $this->assertSame($userB->id, $owned->user_id);
        $this->assertNotSame($original->id, $owned->id);
        $this->assertFalse($owned->trashed());
        $expected = $scanner->formatResult($owned, true);
        // The existing create response does not hydrate this database default.
        $expected['is_quarantined'] = null;
        $this->assertSame($expected, $response->json('results.0'));
        $this->assertNotSame($original->analysis_chain, $owned->analysis_chain);
        $this->assertSame($originalAttributes, $original->fresh()->getRawOriginal());
        foreach (['subject', 'sender', 'snippet'] as $field) {
            $this->assertNotSame($submitted[$field], $owned->getRawOriginal($field));
            $this->assertSame($submitted[$field], $owned->{$field});
        }
        $this->assertDatabaseCount('scanned_emails', 2);
        Http::assertNothingSent();
    }

    public static function deletionCases(): array
    {
        return ['active' => [false], 'soft-deleted' => [true]];
    }

    #[DataProvider('deletionCases')]
    public function test_same_user_retries_return_the_unchanged_original_without_analysis(bool $deleted): void
    {
        $user = User::factory()->create();
        $scanner = app(EmailScannerService::class);
        $result = $scanner->scanAndStore($user, $this->email());
        $this->assertTrue($result['created']);
        $original = $result['record'];
        if ($deleted) {
            $original->delete();
        }
        $attributes = $original->fresh()->getRawOriginal();

        // Every analysis goes through this cache lookup, even in mock mode.
        Cache::shouldReceive('remember')->never();
        $changed = $this->email([
            'subject' => 'Replacement subject',
            'sender' => 'replacement@synthetic.xyz',
            'snippet' => 'Replacement snippet',
            'body' => 'Replacement body',
        ]);
        $retry = $scanner->scanAndStore($user, $changed);
        $this->assertFalse($retry['created']);
        $this->assertSame($original->id, $retry['record']->id);
        $this->assertSame($attributes, $retry['record']->getRawOriginal());

        $this->actingAs($user)->postJson('/api/scan-email', ['emails' => [$changed, $changed]])
            ->assertOk()
            ->assertExactJson(['results' => [
                $scanner->formatResult($original->fresh(), false),
                $scanner->formatResult($original->fresh(), false),
            ]]);

        $this->assertSame($attributes, $original->fresh()->getRawOriginal());
        $this->assertSame($deleted, $original->fresh()->trashed());
        $this->assertDatabaseCount('scanned_emails', 1);
        Http::assertNothingSent();
    }

    #[DataProvider('deletionCases')]
    public function test_database_enforces_the_pair_including_deleted_rows(bool $deleted): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $attributes = [
            'google_message_id' => 'database-shared-message',
            'subject' => 'Synthetic database subject',
            'sender' => 'sender@synthetic.example',
            'snippet' => 'Synthetic database snippet',
        ];
        $original = ScannedEmail::create(array_merge($attributes, [
            'user_id' => $userA->id,
        ]));
        if ($deleted) {
            $original->delete();
        }

        ScannedEmail::create(array_merge($attributes, [
            'user_id' => $userB->id,
        ]));
        $this->assertDatabaseCount('scanned_emails', 2);

        $this->expectException(UniqueConstraintViolationException::class);
        // A savepoint keeps PostgreSQL's surrounding test transaction usable.
        DB::transaction(fn () => ScannedEmail::create(array_merge($attributes, [
            'user_id' => $userA->id,
        ])));
    }

    #[DataProvider('deletionCases')]
    public function test_insert_conflict_returns_only_the_same_users_winning_record(bool $deleted): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $scanner = app(EmailScannerService::class);
        $other = $scanner->scanAndStore($userA, $this->email(['subject' => 'Other user secret']))['record'];
        $other->delete();
        $winner = null;
        $winningAttributes = null;
        $attempts = 0;
        ScannedEmail::creating(function (ScannedEmail $record) use ($userB, &$attempts) {
            if ($record->user_id === $userB->id) {
                $attempts++;
            }
        });

        // Deterministically interleave the winner after the initial SELECT has
        // returned no rows, before the losing INSERT's savepoint is opened.
        $this->afterInitialLookup(function () use ($scanner, $userB, $deleted, &$winner, &$winningAttributes) {
            $winner = $scanner->scanAndStore($userB, $this->email([
                'subject' => 'Winning subject',
                'sender' => 'winner@synthetic.xyz',
                'snippet' => 'Winning snippet',
            ]))['record'];
            if ($deleted) {
                $winner->delete();
            }
            $winningAttributes = $winner->fresh()->getRawOriginal();
        });

        $response = $this->actingAs($userB)->postJson('/api/scan-email', [
            'emails' => [$this->email(['subject' => 'Losing subject', 'user_id' => $userA->id])],
        ])->assertOk();

        $this->assertNotNull($winner);
        $this->assertSame(2, $attempts, 'Both winner and loser must attempt a real database insert.');
        $response->assertExactJson(['results' => [$scanner->formatResult($winner->fresh(), false)]]);
        $this->assertSame($userB->id, $winner->user_id);
        $this->assertSame($deleted, $winner->fresh()->trashed());
        $this->assertSame($winningAttributes, $winner->fresh()->getRawOriginal());
        $this->assertDatabaseCount('scanned_emails', 2);
        Http::assertNothingSent();
    }

    public function test_unique_failure_without_an_owned_winner_is_rethrown(): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $scanner = app(EmailScannerService::class);
        $other = $scanner->scanAndStore($userA, $this->email())['record'];
        // Force an unrelated primary-key collision, with another user's matching
        // message present. Recovery must never fall back to that user's record.
        ScannedEmail::creating(function (ScannedEmail $record) use ($other) {
            $record->id = $other->id;
        });

        $this->expectException(UniqueConstraintViolationException::class);
        $scanner->scanAndStore($userB, $this->email());
    }

    public function test_non_unique_database_failure_is_rethrown_even_if_an_owned_winner_exists(): void
    {
        $user = User::factory()->create();
        $scanner = app(EmailScannerService::class);
        $this->afterInitialLookup(function () use ($scanner, $user) {
            $scanner->scanAndStore($user, $this->email(['subject' => 'Winning subject']));
            ScannedEmail::creating(function (ScannedEmail $record) {
                $record->user_id = null; // Real NOT NULL violation, not a uniqueness race.
            });
        });

        try {
            $scanner->scanAndStore($user, $this->email());
            $this->fail('The unrelated database failure must propagate.');
        } catch (QueryException $exception) {
            $this->assertNotInstanceOf(UniqueConstraintViolationException::class, $exception);
        }
        $this->assertDatabaseCount('scanned_emails', 1);
    }

    public function test_scan_endpoint_requires_authentication(): void
    {
        $this->postJson('/api/scan-email', ['emails' => [$this->email()]])->assertUnauthorized();
        $this->assertDatabaseCount('scanned_emails', 0);
    }

    private function afterInitialLookup(callable $callback): void
    {
        $interleaved = false;
        DB::listen(function (QueryExecuted $query) use ($callback, &$interleaved) {
            if (! $interleaved && str_starts_with($query->sql, 'select') && str_contains($query->sql, 'scanned_emails')) {
                $interleaved = true;
                $callback();
            }
        });
    }

    private function email(array $overrides = []): array
    {
        return array_merge([
            'google_message_id' => 'synthetic-shared-message',
            'subject' => 'Subject supplied by B',
            'sender' => 'sender@synthetic-b.example',
            'snippet' => 'Snippet supplied by B',
            'body' => 'Synthetic body supplied by B',
        ], $overrides);
    }
}
