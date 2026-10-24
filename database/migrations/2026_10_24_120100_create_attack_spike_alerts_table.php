<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('attack_spike_alerts', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('company_id')->index();
            $table->unsignedBigInteger('monitored_domain_id')->index();
            $table->string('severity', 16);
            $table->string('status', 16)->default('pending');
            $table->timestamp('detected_at');
            $table->unsignedInteger('events_in_window');
            $table->unsignedInteger('monitoring_window_minutes');
            $table->unsignedInteger('high_threshold');
            $table->unsignedInteger('critical_threshold');
            $table->unsignedInteger('new_events_added_during_latest_sync')->default(0);
            $table->json('outcomes')->nullable();
            $table->json('delivered_channels')->nullable();
            $table->string('delivery_lock_token')->nullable()->index();
            $table->timestamp('delivery_lock_expires_at')->nullable();
            $table->timestamp('last_attempt_at')->nullable();
            $table->timestamp('delivered_at')->nullable();
            $table->timestamps();

            $table->index(['monitored_domain_id', 'status']);
            $table->index(['company_id', 'monitored_domain_id', 'severity', 'delivered_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('attack_spike_alerts');
    }
};
