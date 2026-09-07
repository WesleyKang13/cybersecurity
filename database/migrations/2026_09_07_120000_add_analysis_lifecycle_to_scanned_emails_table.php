<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->string('analysis_status')->default('completed')->after('final_reasoning');
            $table->unsignedTinyInteger('analysis_attempts')->default(0)->after('analysis_status');
            $table->string('analysis_last_error_code')->nullable()->after('analysis_attempts');
            $table->timestamp('analysis_last_attempted_at')->nullable()->after('analysis_last_error_code');
            $table->timestamp('analysis_completed_at')->nullable()->after('analysis_last_attempted_at');
            $table->timestamp('analysis_next_retry_at')->nullable()->after('analysis_completed_at');
            $table->string('analysis_lease_token')->nullable()->after('analysis_next_retry_at');
            $table->timestamp('analysis_lease_expires_at')->nullable()->after('analysis_lease_token');
            $table->text('analysis_retry_payload')->nullable()->after('analysis_lease_expires_at');
            $table->timestamp('alert_sent_at')->nullable()->after('analysis_retry_payload');
            $table->index(['analysis_status', 'analysis_next_retry_at']);
        });

        DB::table('scanned_emails')->update([
            'analysis_status' => 'completed',
            'analysis_completed_at' => DB::raw('created_at'),
        ]);

        DB::table('scanned_emails')
            ->where('detection_layer', 'Layer 3 (AI Error)')
            ->update([
                'analysis_status' => 'failed',
                'analysis_last_error_code' => 'legacy_ai_error',
                'analysis_completed_at' => null,
                'analysis_next_retry_at' => null,
                'verdict' => 'INCONCLUSIVE',
                'severity' => 'inconclusive',
                'risk_score' => 1,
                'is_threat' => false,
                'reason' => 'Analysis is unavailable and requires a retry.',
                'final_reasoning' => 'Analysis is unavailable and requires a retry.',
            ]);
    }

    public function down(): void
    {
        if (DB::table('scanned_emails')->where('analysis_status', '!=', 'completed')->exists()) {
            throw new RuntimeException('Cannot remove analysis lifecycle columns while incomplete scans exist. Resolve or retain them before rollback; no rows were changed.');
        }

        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropIndex(['analysis_status', 'analysis_next_retry_at']);
            $table->dropColumn([
                'analysis_status', 'analysis_attempts', 'analysis_last_error_code', 'analysis_last_attempted_at',
                'analysis_completed_at', 'analysis_next_retry_at', 'analysis_lease_token', 'analysis_lease_expires_at',
                'analysis_retry_payload', 'alert_sent_at',
            ]);
        });
    }
};
