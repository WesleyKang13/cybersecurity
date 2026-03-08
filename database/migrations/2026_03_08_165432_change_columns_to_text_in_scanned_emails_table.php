<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            // Upgrades the columns to handle massive encrypted strings
            $table->text('subject')->change();
            $table->text('sender')->change();
            $table->text('snippet')->change();
        });
    }

    public function down(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            // Reverts them back if you ever rollback
            $table->string('subject', 255)->change();
            $table->string('sender', 255)->change();
            $table->string('snippet', 255)->change();
        });
    }
};
