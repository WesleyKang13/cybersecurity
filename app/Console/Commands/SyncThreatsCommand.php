<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\CloudflareThreatService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

class SyncThreatsCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'app:sync-threats';

    /**
     * @var string
     */
    protected $description = 'Process recent Tier 2 Cloudflare threats and Tier 3 middleware telemetry for owned domains';

    public function handle(CloudflareThreatService $cloudflareThreatService): int
    {
        $this->info('Processing owned domain threats across Tier 2 Cloudflare and Tier 3 middleware integrations...');

        $summary = $cloudflareThreatService->syncOwnedDomains();

        $this->line(sprintf('Domains processed: %d', $summary['domains_processed']));
        $this->line(sprintf('Events synced: %d', $summary['events_synced']));
        $this->line(sprintf('Domains skipped: %d', $summary['skipped']));

        if ($summary['failed'] > 0) {
            $this->warn(sprintf('Domains failed: %d', $summary['failed']));
        } else {
            $this->info('Threat sync completed without domain-level failures.');
        }

        Cache::put('threats_last_synced', now());

        return self::SUCCESS;
    }
}
