<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\ScannedEmail;
use App\Models\User;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\TestCase;

class ScannedEmailOwnershipMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_upgrade_preserves_existing_rows_and_ciphertext(): void
    {
        $migration = $this->migration();
        $migration->down();
        $this->assertTrue(Schema::hasIndex('scanned_emails', ['google_message_id'], 'unique'));
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $active = $this->record($userA, 'historical-active');
        $deleted = $this->record($userB, 'historical-deleted');
        $deleted->delete();
        $before = $this->rawRows();

        $migration->up();

        $this->assertSame($before, $this->rawRows());
        $this->assertFalse($active->fresh()->trashed());
        $this->assertTrue($deleted->fresh()->trashed());
        foreach ([$active, $deleted] as $record) {
            foreach (['subject', 'sender', 'snippet'] as $field) {
                $this->assertSame($record->{$field}, $record->fresh()->{$field});
                $this->assertNotSame($record->{$field}, $record->fresh()->getRawOriginal($field));
            }
        }
        $this->assertTrue(Schema::hasIndex('scanned_emails', ['user_id', 'google_message_id'], 'unique'));
        $this->assertFalse(Schema::hasIndex('scanned_emails', ['google_message_id'], 'unique'));
        $this->record($userB, $active->google_message_id);
        $this->assertDatabaseCount('scanned_emails', 3);
    }

    public static function deletionCases(): array
    {
        return ['active collision' => [false], 'soft-deleted collision' => [true]];
    }

    #[DataProvider('deletionCases')]
    public function test_incompatible_rollback_leaves_all_records_and_indexes_intact(bool $deleted): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $first = $this->record($userA, 'legitimate-shared-message');
        $second = $this->record($userB, $first->google_message_id);
        if ($deleted) {
            $second->delete();
        }
        $before = $this->rawRows();
        $indexes = Schema::getIndexes('scanned_emails');

        try {
            $this->migration()->down();
            $this->fail('Rollback must refuse globally duplicated message IDs.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('Cannot restore global scanned-email message ID uniqueness', $exception->getMessage());
            $this->assertStringContainsString('including soft-deleted records', $exception->getMessage());
        }

        $this->assertSame($before, $this->rawRows());
        $this->assertSame($indexes, Schema::getIndexes('scanned_emails'));
        $this->assertSame($deleted, $second->fresh()->trashed());

        $this->expectException(UniqueConstraintViolationException::class);
        DB::transaction(fn () => $this->record($userA, $first->google_message_id));
    }

    public function test_compatible_rollback_restores_global_uniqueness_without_changing_rows(): void
    {
        $userA = User::factory()->create();
        $userB = User::factory()->create();
        $record = $this->record($userA, 'unique-historical-message');
        $record->delete();
        $before = $this->rawRows();

        $this->migration()->down();

        $this->assertSame($before, $this->rawRows());
        $this->assertTrue(Schema::hasIndex('scanned_emails', ['google_message_id'], 'unique'));
        $this->assertFalse(Schema::hasIndex('scanned_emails', ['user_id', 'google_message_id'], 'unique'));
        $this->expectException(UniqueConstraintViolationException::class);
        DB::transaction(fn () => $this->record($userB, $record->google_message_id));
    }

    private function migration(): Migration
    {
        return require database_path('migrations/2026_09_05_120000_scope_scanned_email_message_ids_to_users.php');
    }

    private function rawRows(): array
    {
        return DB::table('scanned_emails')->orderBy('id')->get()
            ->map(fn (object $record) => (array) $record)->all();
    }

    private function record(User $user, string $messageId): ScannedEmail
    {
        return ScannedEmail::create([
            'user_id' => $user->id,
            'google_message_id' => $messageId,
            'subject' => 'Synthetic historical subject — résumé',
            'sender' => 'historical@synthetic.example',
            'snippet' => str_repeat('Synthetic historical encrypted content. ', 20),
            'is_threat' => true,
            'severity' => 'high',
            'risk_score' => 95,
            'detection_layer' => 'Layer 3 (AI Analysis)',
            'reason' => 'Synthetic historical reason',
            'verdict' => 'MALICIOUS',
            'threat_category' => 'Phishing',
            'analysis_chain' => ['Synthetic historical analysis'],
            'final_reasoning' => 'Synthetic historical reasoning',
            'origin_trace' => ['originating_ip' => '192.0.2.10'],
            'is_quarantined' => true,
        ]);
    }
}
