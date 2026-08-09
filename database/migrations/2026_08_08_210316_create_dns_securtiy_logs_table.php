<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('dns_security_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->string('record_type'); // A, MX, TXT, CNAME, etc.
            $table->text('expected_value')->nullable();
            $table->text('current_value');
            $table->string('severity')->default('info'); // info, warning, high, critical
            $table->string('status'); // secure, mismatch, vulnerable, missing
            $table->text('description');
            $table->timestamp('resolved_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('dns_security_logs');
    }
};
