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

    /*
     * These are deliberately not constructor-promoted properties. Jobs serialized before
     * the run ID was introduced do not contain scanRunId, and must still be runnable.
     */
    public int $domainId;

    public int $companyId;

    public ?string $scanRunId = null;

    public function __construct(int $domainId, int $companyId, ?string $scanRunId = null)
    {
        $this->domainId = $domainId;
        $this->companyId = $companyId;
        $this->scanRunId = $scanRunId;
    }

    public function uniqueId(): string
    {
        return "{$this->companyId}:{$this->domainId}";
    }

    public function handle(DnsScannerService $scanner, UniversalSecurityScannerService $webSecurityScanner): void
    {
        $claimed = $this->currentRunQuery()
            ->where('universal_scan_status', 'queued')
            ->update([
                'universal_scan_status' => 'running',
                'universal_scan_started_at' => now(),
                'universal_scan_failed_at' => null,
                'universal_scan_error' => null,
            ]);

        if ($claimed !== 1) {
            return;
        }

        $domain = MonitoredDomain::query()
            ->whereKey($this->domainId)
            ->where('company_id', $this->companyId)
            ->first();

        if ($domain === null) {
            return;
        }

        $scanner->scan($domain);
        $webSecurityScanner->scan($domain);

        $this->currentRunQuery()
            ->where('universal_scan_status', 'running')
            ->update([
                'universal_scan_status' => 'completed',
                'universal_scan_completed_at' => now(),
                'universal_scan_failed_at' => null,
                'universal_scan_error' => null,
            ]);
    }

    public function failed(?Throwable $exception): void
    {
        $failed = $this->currentRunQuery()
            ->whereIn('universal_scan_status', ['queued', 'running'])
            ->update([
                'universal_scan_status' => 'failed',
                'universal_scan_failed_at' => now(),
                'universal_scan_error' => 'The scan could not complete. Please try again.',
            ]);

        if ($failed === 1) {
            Log::warning('Universal security scan failed.', [
                'domain_id' => $this->domainId,
                'company_id' => $this->companyId,
                'scan_run_id' => $this->scanRunId,
                'exception_class' => $exception !== null ? $exception::class : null,
            ]);
        }
    }

    private function currentRunQuery()
    {
        return MonitoredDomain::query()
            ->whereKey($this->domainId)
            ->where('company_id', $this->companyId)
            ->where(function ($query): void {
                if ($this->scanRunId === null) {
                    $query->whereNull('universal_scan_run_id');

                    return;
                }

                $query->where('universal_scan_run_id', $this->scanRunId);
            });
    }
}
