<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // 1. Create Companies Table (The Tenant)
        Schema::create('companies', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('domain')->unique()->nullable();
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });

        // 2. Add company_id to Users Table (Link User -> Company)
        Schema::table('users', function (Blueprint $table) {
            $table->foreignId('company_id')->nullable()->constrained()->onDelete('cascade');
            $table->string('role')->default('member'); // 'admin' or 'member'
        });

        // 3. Create OAuth Tokens Table (Store Gmail Keys)
        Schema::create('oauth_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('company_id')->constrained()->onDelete('cascade');
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->string('provider')->default('google'); // 'google' or 'microsoft'
            $table->text('access_token');   // The key to read emails
            $table->text('refresh_token')->nullable(); // The key to stay logged in
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_tokens');
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['company_id', 'role']);
        });
        Schema::dropIfExists('companies');
    }
};
