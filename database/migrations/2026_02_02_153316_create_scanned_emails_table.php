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
        Schema::create('scanned_emails', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade'); // Links to the User
            $table->string('google_message_id')->unique(); // Prevents scanning the same email twice
            $table->string('subject')->nullable();
            $table->string('sender')->nullable();
            $table->text('snippet')->nullable(); // A short preview of the email body
            $table->boolean('is_threat')->default(false);
            $table->string('severity')->default('clean'); // 'clean', 'low', 'high'
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scanned_emails');
    }
};
