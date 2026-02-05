<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

return new class extends Migration
{
    public function up(): void
    {
        DB::table('users')->insert([
            'name'              => 'Super Admin',
            'email'             => 'admin@example.com',
            'password'          => Hash::make('password123'),
            'email_verified_at' => now(),
            'role'              => 'admin',
            'token'             => null,
            'company_id'        => null,
            'organization_id'   => null,

            'created_at'        => now(),
            'updated_at'        => now(),
        ]);
    }

    public function down(): void
    {
        DB::table('users')->where('email', 'admin@example.com')->delete();
    }
};
