<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use App\Models\Company;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        // 1. Create the Company
        $company = Company::create([
            'name' => 'CyberSafe Sdn Bhd',
            'domain' => 'cybersafe.com.my',
            'is_active' => true,
        ]);

        // 2. Create the Admin User
        User::create([
            'name' => 'Admin User',
            'email' => 'admin@cybersafe.com.my',
            'password' => Hash::make('password'), // The login password
            'company_id' => $company->id,
            'role' => 'admin',
        ]);

        echo "✅ Company and Admin User created successfully!\n";
        echo "👉 Login Email: admin@cybersafe.com.my\n";
        echo "👉 Password: password\n";
    }
}
