<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->boolean('is_quarantined')->default(false)->after('is_threat');
        });
    }

    public function down(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropColumn('is_quarantined');
        });
    }
};
