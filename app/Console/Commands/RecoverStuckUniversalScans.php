<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\MonitoredDomain;
use Illuminate\Console\Command;

class RecoverStuckUniversalScans extends Command
{
    protected $signature = 'app:recover-stuck-universal-scans';

    protected $description = 'Fail universal scans that have been queued or running for more than 30 minutes';

    public function handle(): int
    {
        $cutoff = now()->subMinutes(30);
        $failureState = [
            'universal_scan_status' => 'failed',
            'universal_scan_run_id' => null,
            'universal_scan_failed_at' => now(),
            'universal_scan_error' => 'The scan timed out before it could complete. Please try again.',
        ];

        $queued = MonitoredDomain::query()
            ->where('universal_scan_status', 'queued')
            ->where('universal_scan_requested_at', '<', $cutoff)
            ->update($failureState);

        $running = MonitoredDomain::query()
            ->where('universal_scan_status', 'running')
            ->where('universal_scan_started_at', '<', $cutoff)
            ->update($failureState);

        $this->info(sprintf('Recovered %d stuck universal scan(s).', $queued + $running));

        return self::SUCCESS;
    }
}
