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
            $table->string('event_type', 100)->nullable()->after('user_agent');
            $table->string('severity', 16)->nullable()->after('event_type');
            $table->text('reason')->nullable()->after('severity');
            $table->json('metadata')->nullable()->after('reason');
        });
    }

    public function down(): void
    {
        Schema::table('security_threat_logs', function (Blueprint $table): void {
            $table->dropColumn(['event_type', 'severity', 'reason', 'metadata']);
        });
    }
};
