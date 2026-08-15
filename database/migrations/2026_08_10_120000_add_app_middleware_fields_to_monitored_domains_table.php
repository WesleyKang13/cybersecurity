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
            $table->string('infrastructure_type')->default('cloudflare')->after('domain');
            $table->string('app_secret_token', 64)->nullable()->unique()->after('infrastructure_type');
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropColumn([
                'infrastructure_type',
                'app_secret_token',
            ]);
        });
    }
};
