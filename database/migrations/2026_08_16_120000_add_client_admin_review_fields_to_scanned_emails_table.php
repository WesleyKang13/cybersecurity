<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->timestamp('admin_reviewed_at')->nullable()->after('origin_trace');
            $table->foreignId('admin_reviewed_by_user_id')
                ->nullable()
                ->after('admin_reviewed_at')
                ->constrained('users')
                ->nullOnDelete();
            $table->index(
                ['is_threat', 'severity', 'admin_reviewed_at'],
                'scanned_emails_client_review_idx'
            );
        });
    }

    public function down(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropIndex('scanned_emails_client_review_idx');
            $table->dropConstrainedForeignId('admin_reviewed_by_user_id');
            $table->dropColumn('admin_reviewed_at');
        });
    }
};
