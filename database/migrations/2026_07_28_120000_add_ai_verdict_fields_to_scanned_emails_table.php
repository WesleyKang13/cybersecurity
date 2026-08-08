<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->string('verdict')->nullable()->after('risk_score');
            $table->string('threat_category')->nullable()->after('verdict');
            $table->json('analysis_chain')->nullable()->after('threat_category');
            $table->text('final_reasoning')->nullable()->after('analysis_chain');
        });
    }

    public function down(): void
    {
        Schema::table('scanned_emails', function (Blueprint $table) {
            $table->dropColumn(['verdict', 'threat_category', 'analysis_chain', 'final_reasoning']);
        });
    }
};
