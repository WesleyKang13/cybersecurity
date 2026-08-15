<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_threat_logs', function (Blueprint $table): void {
            $table->text('user_agent')->nullable()->after('path_targeted');
        });
    }

    public function down(): void
    {
        Schema::table('security_threat_logs', function (Blueprint $table): void {
            $table->dropColumn('user_agent');
        });
    }
};
