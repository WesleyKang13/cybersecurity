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
            $table->uuid('universal_scan_run_id')
                ->nullable()
                ->after('universal_scan_status')
                ->index();
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropIndex(['universal_scan_run_id']);
            $table->dropColumn('universal_scan_run_id');
        });
    }
};
