<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Establish the replacement before removing the old constraint. No row data
        // is rewritten, including encrypted content and soft-delete timestamps.
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->unique(['user_id', 'google_message_id']);
        });

        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropUnique(['google_message_id']);
        });
    }

    public function down(): void
    {
        // Query raw rows so soft-deleted messages also block an unsafe rollback.
        if (DB::table('scanned_emails')
            ->select('google_message_id')
            ->groupBy('google_message_id')
            ->havingRaw('COUNT(*) > 1')
            ->exists()) {
            throw new RuntimeException(
                'Cannot restore global scanned-email message ID uniqueness: multiple users '
                .'share a google_message_id (including soft-deleted records). Keep the '
                .'user-scoped constraint; rollback requires globally unique data. No records were changed.'
            );
        }

        // Add first: even a conflicting insert after the preflight cannot leave
        // the table without the composite constraint. Pause scan writers to roll back.
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->unique('google_message_id');
        });

        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropUnique(['user_id', 'google_message_id']);
        });
    }
};
