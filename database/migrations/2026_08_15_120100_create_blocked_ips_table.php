<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blocked_ips', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('monitored_domain_id')->nullable()->constrained()->nullOnDelete();
            $table->string('ip', 45);
            $table->boolean('is_global')->default(false);
            $table->text('reason')->nullable();
            $table->timestamps();

            $table->index('ip');
            $table->index(['monitored_domain_id', 'is_global']);
            $table->unique(['monitored_domain_id', 'ip', 'is_global'], 'blocked_ips_domain_ip_global_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blocked_ips');
    }
};
