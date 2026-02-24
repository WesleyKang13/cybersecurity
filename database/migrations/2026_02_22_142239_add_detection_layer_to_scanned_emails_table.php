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
            // We make it nullable just in case old records don't have it
            $table->string('detection_layer')->nullable()->after('is_threat');
        });
    }

    public function down(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropColumn('detection_layer');
        });
    }
};
