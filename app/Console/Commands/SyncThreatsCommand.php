<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Services\CloudflareThreatService;
use Illuminate\Console\Command;

class SyncThreatsCommand extends Command
{
    /**
     * @var string
     */
    protected $signature = 'app:sync-threats';

    /**
     * @var string
     */
    protected $description = 'Sync recent Cloudflare firewall events for owned domains';

    public function handle(CloudflareThreatService $cloudflareThreatService): int
    {
        $this->info('Syncing Cloudflare firewall events for owned domains...');

        $summary = $cloudflareThreatService->syncOwnedDomains();

        $this->line(sprintf('Domains processed: %d', $summary['domains_processed']));
        $this->line(sprintf('Events synced: %d', $summary['events_synced']));
        $this->line(sprintf('Domains skipped: %d', $summary['skipped']));

        if ($summary['failed'] > 0) {
            $this->warn(sprintf('Domains failed: %d', $summary['failed']));
        } else {
            $this->info('Threat sync completed without domain-level failures.');
        }

        return self::SUCCESS;
    }
}
