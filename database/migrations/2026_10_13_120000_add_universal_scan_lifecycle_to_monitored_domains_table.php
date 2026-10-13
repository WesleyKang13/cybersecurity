<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->string('universal_scan_status', 16)->nullable()->after('last_checked_at');
            $table->timestamp('universal_scan_requested_at')->nullable()->after('universal_scan_status');
            $table->timestamp('universal_scan_started_at')->nullable()->after('universal_scan_requested_at');
            $table->timestamp('universal_scan_completed_at')->nullable()->after('universal_scan_started_at');
            $table->timestamp('universal_scan_failed_at')->nullable()->after('universal_scan_completed_at');
            $table->string('universal_scan_error')->nullable()->after('universal_scan_failed_at');
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropColumn([
                'universal_scan_status',
                'universal_scan_requested_at',
                'universal_scan_started_at',
                'universal_scan_completed_at',
                'universal_scan_failed_at',
                'universal_scan_error',
            ]);
        });
    }
};
