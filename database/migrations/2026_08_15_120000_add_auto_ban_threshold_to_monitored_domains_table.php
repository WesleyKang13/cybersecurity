<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->unsignedInteger('auto_ban_threshold')->default(10)->after('cloudflare_zone_id');
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropColumn('auto_ban_threshold');
        });
    }
};
