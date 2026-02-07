<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up()
    {
        Schema::table('scanned_emails', function ($table) {
            $table->softDeletes(); 
        });

        Schema::table('scanned_sms', function ($table) {
            $table->softDeletes();
        });
    }

    public function down()
    {
        Schema::table('scanned_emails', function ($table) {
            $table->dropSoftDeletes();
        });

        Schema::table('scanned_sms', function ($table) {
            $table->dropSoftDeletes();
        });
    }
};
