<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('web_security_scans', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->unsignedSmallInteger('http_status')->nullable();
            $table->unsignedInteger('response_time_ms')->nullable();
            $table->boolean('ssl_valid')->default(false);
            $table->timestamp('ssl_expires_at')->nullable();
            $table->string('ssl_issuer')->nullable();
            $table->json('missing_headers')->nullable();
            $table->unsignedTinyInteger('security_score')->default(0);
            $table->json('detected_issues')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('web_security_scans');
    }
};
