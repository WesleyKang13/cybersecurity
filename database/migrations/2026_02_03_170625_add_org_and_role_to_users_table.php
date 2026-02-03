<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {

            // 1. Check if 'organization_id' exists before adding
            if (!Schema::hasColumn('users', 'organization_id')) {
                $table->unsignedBigInteger('organization_id')->nullable()->index();
            }

            // 2. Check if 'role' exists before adding
            if (!Schema::hasColumn('users', 'role')) {
                $table->string('role')->default('user');
            }
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['organization_id', 'role']);
        });
    }
};
