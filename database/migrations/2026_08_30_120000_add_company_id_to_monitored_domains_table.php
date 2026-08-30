<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public $withinTransaction = true;

    public function up(): void
    {
        $existingDomainCount = DB::table('monitored_domains')->count();
        $platformCompanyId = null;

        if ($existingDomainCount > 0) {
            $platformCompanyIds = DB::table('companies')
                ->where('type', 'platform')
                ->orderBy('id')
                ->pluck('id');

            if ($platformCompanyIds->count() !== 1) {
                throw new \LogicException(
                    'Exactly one platform company is required to assign existing monitored domains safely.'
                );
            }

            $platformCompanyId = (int) $platformCompanyIds->first();
        }

        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->foreignId('company_id')
                ->nullable()
                ->after('id')
                ->constrained('companies')
                ->restrictOnDelete();
        });

        if ($platformCompanyId !== null) {
            DB::table('monitored_domains')
                ->whereNull('company_id')
                ->update(['company_id' => $platformCompanyId]);
        }

        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->foreignId('company_id')->nullable(false)->change();
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('company_id');
        });
    }
};
