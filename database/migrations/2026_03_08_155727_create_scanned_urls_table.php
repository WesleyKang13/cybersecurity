<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('scanned_urls', function (Blueprint $table) {
            $table->id();
            $table->text('url'); // The actual link
            $table->boolean('is_malicious'); // True if VirusTotal flags it
            $table->integer('malicious_votes')->default(0); // How many security vendors flagged it
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scanned_urls');
    }
};
