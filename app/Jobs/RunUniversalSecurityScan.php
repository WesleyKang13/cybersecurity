<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Models\MonitoredDomain;
use App\Services\DnsScannerService;
use App\Services\UniversalSecurityScannerService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Throwable;

class RunUniversalSecurityScan implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 1;

    public int $uniqueFor = 900;

    public function __construct(
        public readonly int $domainId,
        public readonly int $companyId,
    ) {}

    public function uniqueId(): string
    {
        return "{$this->companyId}:{$this->domainId}";
    }

    public function handle(DnsScannerService $scanner, UniversalSecurityScannerService $webSecurityScanner): void
    {
        $domain = MonitoredDomain::query()
            ->whereKey($this->domainId)
            ->where('company_id', $this->companyId)
            ->first();

        if ($domain === null) {
            return;
        }

        $domain->forceFill([
            'universal_scan_status' => 'running',
            'universal_scan_started_at' => now(),
            'universal_scan_failed_at' => null,
            'universal_scan_error' => null,
        ])->save();

        $scanner->scan($domain);
        $webSecurityScanner->scan($domain);

        $domain->forceFill([
            'universal_scan_status' => 'completed',
            'universal_scan_completed_at' => now(),
            'universal_scan_failed_at' => null,
            'universal_scan_error' => null,
        ])->save();
    }

    public function failed(?Throwable $exception): void
    {
        $domain = MonitoredDomain::query()
            ->whereKey($this->domainId)
            ->where('company_id', $this->companyId)
            ->first();

        if ($domain !== null) {
            $domain->forceFill([
                'universal_scan_status' => 'failed',
                'universal_scan_failed_at' => now(),
                'universal_scan_error' => 'The scan could not complete. Please try again.',
            ])->save();
        }

        Log::warning('Universal security scan failed.', [
            'domain_id' => $this->domainId,
            'company_id' => $this->companyId,
            'exception_class' => $exception !== null ? $exception::class : null,
        ]);
    }
}
