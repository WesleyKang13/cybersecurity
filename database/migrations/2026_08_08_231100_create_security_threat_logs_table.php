<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_threat_logs', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->string('attacker_ip');
            $table->string('country')->nullable();
            $table->string('path_targeted')->nullable();
            $table->string('action_taken');
            $table->string('threat_source')->nullable();
            $table->timestamp('detected_at');
            $table->timestamps();

            $table->index(['monitored_domain_id', 'detected_at']);
            $table->unique(
                ['monitored_domain_id', 'attacker_ip', 'path_targeted', 'detected_at'],
                'security_threat_logs_unique_event'
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_threat_logs');
    }
};
