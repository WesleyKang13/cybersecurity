<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\MonitoredDomain;
use App\Services\DnsScannerService;
use App\Services\UniversalSecurityScannerService;
use Illuminate\Console\Command;
use Throwable;

class ScanDnsCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'app:scan-dns';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan active monitored domains for DNS drift, email security misconfigurations, and web security health';

    public function handle(
        DnsScannerService $dnsScannerService,
        UniversalSecurityScannerService $webSecurityScanner
    ): int
    {
        $domains = MonitoredDomain::query()
            ->where('is_active', true)
            ->orderBy('domain')
            ->get();

        if ($domains->isEmpty()) {
            $this->warn('No active monitored domains were found.');

            return self::SUCCESS;
        }

        $this->info(sprintf('Scanning %d active monitored domain(s)...', $domains->count()));

        $progressBar = $this->output->createProgressBar($domains->count());
        $progressBar->setFormat('%current%/%max% [%bar%] %percent:3s%% %message%');
        $progressBar->setMessage('initializing');
        $progressBar->start();

        $summary = [
            'domains_scanned' => 0,
            'vulnerabilities' => 0,
            'critical' => 0,
            'high' => 0,
            'warning' => 0,
            'failed' => 0,
        ];

        foreach ($domains as $domain) {
            $progressBar->setMessage($domain->domain);

            try {
                $result = $dnsScannerService->scan($domain);
                $webSecurityScanner->scan($domain);
                $summary['domains_scanned']++;
                $summary['vulnerabilities'] += $result['vulnerability_count'];
                $summary['critical'] += $result['by_severity']['critical'];
                $summary['high'] += $result['by_severity']['high'];
                $summary['warning'] += $result['by_severity']['warning'];
            } catch (Throwable $e) {
                $summary['failed']++;
                $this->newLine();
                $this->error(sprintf('Failed to scan %s: %s', $domain->domain, $e->getMessage()));
            }

            $progressBar->advance();
        }

        $progressBar->finish();
        $this->newLine(2);

        $this->info('DNS Security Scan Summary');
        $this->line(sprintf('Domains scanned: %d', $summary['domains_scanned']));
        $this->line(sprintf('Vulnerabilities found: %d', $summary['vulnerabilities']));
        $this->line(sprintf('Critical findings: %d', $summary['critical']));
        $this->line(sprintf('High findings: %d', $summary['high']));
        $this->line(sprintf('Warning findings: %d', $summary['warning']));

        if ($summary['failed'] > 0) {
            $this->warn(sprintf('Failed scans: %d', $summary['failed']));
        }

        if ($summary['vulnerabilities'] > 0) {
            $this->warn('One or more DNS security issues were detected.');
        } else {
            $this->info('No DNS security issues were detected.');
        }

        return self::SUCCESS;
    }
}
