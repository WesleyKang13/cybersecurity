<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $statusWasAdded = false;

        if (Schema::hasTable('companies') && ! Schema::hasColumn('companies', 'type')) {
            Schema::table('companies', function (Blueprint $table) {
                $table->string('type')->default('client');
            });
        }

        if (Schema::hasTable('companies') && ! Schema::hasColumn('companies', 'status')) {
            Schema::table('companies', function (Blueprint $table) {
                $table->string('status')->default('active');
            });

            $statusWasAdded = true;
        }

        if (
            $statusWasAdded
            && Schema::hasColumn('companies', 'is_active')
        ) {
            DB::table('companies')
                ->where('is_active', false)
                ->update(['status' => 'inactive']);
        }

        if (
            Schema::hasTable('users')
            && Schema::hasTable('companies')
            && Schema::hasColumn('users', 'company_id')
            && Schema::hasColumn('users', 'organization_id')
        ) {
            DB::table('users')
                ->whereNull('company_id')
                ->whereNotNull('organization_id')
                ->whereExists(function ($query) {
                    $query->selectRaw('1')
                        ->from('companies')
                        ->whereColumn('companies.id', 'users.organization_id');
                })
                ->update(['company_id' => DB::raw('organization_id')]);
        }
    }

    public function down(): void
    {
        // Backfilled ownership remains intact because it may have become canonical data.
        if (Schema::hasTable('companies') && Schema::hasColumn('companies', 'status')) {
            Schema::table('companies', function (Blueprint $table) {
                $table->dropColumn('status');
            });
        }

        if (Schema::hasTable('companies') && Schema::hasColumn('companies', 'type')) {
            Schema::table('companies', function (Blueprint $table) {
                $table->dropColumn('type');
            });
        }
    }
};
