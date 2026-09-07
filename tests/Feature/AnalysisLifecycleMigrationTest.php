<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\ScannedEmail;
use App\Models\User;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use RuntimeException;
use Tests\TestCase;

class AnalysisLifecycleMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_upgrade_marks_legacy_ai_errors_inconclusive_without_touching_encrypted_content(): void
    {
        $migration = $this->migration();
        $migration->down();
        $user = User::factory()->create();
        $record = ScannedEmail::create([
            'user_id' => $user->id, 'google_message_id' => 'legacy-ai-error',
            'subject' => 'Encrypted subject', 'sender' => 'sender@example.test', 'snippet' => 'Encrypted snippet',
            'is_threat' => false, 'severity' => 'clean', 'risk_score' => 0,
            'detection_layer' => 'Layer 3 (AI Error)', 'reason' => 'AI unavailable.',
            'verdict' => 'SAFE', 'threat_category' => 'None', 'analysis_chain' => ['Legacy failure'],
            'final_reasoning' => 'AI unavailable.',
        ]);
        $rawSubject = $record->getRawOriginal('subject');

        $migration->up();
        $upgraded = $record->fresh();

        $this->assertTrue(Schema::hasColumn('scanned_emails', 'analysis_status'));
        $this->assertSame('failed', $upgraded->analysis_status);
        $this->assertSame('INCONCLUSIVE', $upgraded->verdict);
        $this->assertSame('inconclusive', $upgraded->severity);
        $this->assertSame('legacy_ai_error', $upgraded->analysis_last_error_code);
        $this->assertSame($rawSubject, $upgraded->getRawOriginal('subject'));
        $this->assertSame('Encrypted subject', $upgraded->subject);
    }

    public function test_rollback_refuses_to_discard_incomplete_lifecycle_state(): void
    {
        $record = ScannedEmail::create([
            'user_id' => User::factory()->create()->id,
            'google_message_id' => 'pending-rollback',
            'subject' => 'Pending', 'sender' => 'sender@example.test', 'snippet' => 'Pending',
            'is_threat' => false, 'detection_layer' => 'Layer 3 (Analysis Incomplete)',
            'analysis_status' => 'retry_pending',
            'verdict' => 'INCONCLUSIVE',
            'severity' => 'inconclusive',
            'risk_score' => 1, 'reason' => 'Pending', 'threat_category' => 'None',
            'analysis_chain' => ['Pending'], 'final_reasoning' => 'Pending',
        ]);

        try {
            $this->migration()->down();
            $this->fail('Rollback must not discard an incomplete scan lifecycle.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('Cannot remove analysis lifecycle columns', $exception->getMessage());
        }

        $this->assertSame('retry_pending', $record->fresh()->analysis_status);
    }

    private function migration(): Migration
    {
        return require database_path('migrations/2026_09_07_120000_add_analysis_lifecycle_to_scanned_emails_table.php');
    }
}
