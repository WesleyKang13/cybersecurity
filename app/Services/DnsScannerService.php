<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\DnsSecurityLog;
use App\Models\MonitoredDomain;
use App\Notifications\SecurityAlertNotification;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

class DnsScannerService
{
    private const DNS_TIMEOUT_SECONDS = 5;

    public function __construct(
        private readonly SecurityAlertDispatcher $securityAlertDispatcher
    ) {
    }

    /**
     * Common DKIM selectors used by major providers and common MTAs.
     *
     * @var list<string>
     */
    private const COMMON_DKIM_SELECTORS = [
        'default',
        'google',
        'selector1',
        'selector2',
        'k1',
        'mail',
        'dkim',
        's1',
        'smtpapi',
    ];

    /**
     * @return array{
     *     domain: string,
     *     checked_at: \Illuminate\Support\Carbon,
     *     logs: \Illuminate\Support\Collection<int, \App\Models\DnsSecurityLog>,
     *     vulnerability_count: int,
     *     by_severity: array{info: int, warning: int, high: int, critical: int}
     * }
     */
    public function scan(MonitoredDomain $monitoredDomain): array
    {
        $checkedAt = now();
        $logs = collect();

        $aRecords = $this->lookupDnsRecords($monitoredDomain->domain, DNS_A);
        $mxRecords = $this->lookupDnsRecords($monitoredDomain->domain, DNS_MX);
        $txtRecords = $this->lookupDnsRecords($monitoredDomain->domain, DNS_TXT);
        $dmarcRecords = $this->lookupDnsRecords('_dmarc.' . $monitoredDomain->domain, DNS_TXT);

        $logs->push($this->evaluateAddressRecords($monitoredDomain, 'A', $aRecords, $checkedAt));
        $logs->push($this->evaluateMailExchangeRecords($monitoredDomain, $mxRecords, $checkedAt));

        foreach ($this->evaluateSpfRecords($monitoredDomain, $txtRecords, $checkedAt) as $log) {
            $logs->push($log);
        }

        foreach ($this->evaluateDmarcRecords($monitoredDomain, $dmarcRecords, $checkedAt) as $log) {
            $logs->push($log);
        }

        $logs->push($this->evaluateDkimRecords($monitoredDomain, $checkedAt));

        $monitoredDomain->forceFill([
            'last_checked_at' => $checkedAt,
        ])->save();

        $this->dispatchDnsDriftAlerts($monitoredDomain, $logs);

        $vulnerabilityCount = $logs->filter(fn (DnsSecurityLog $log): bool => $log->status !== 'secure')->count();

        return [
            'domain' => $monitoredDomain->domain,
            'checked_at' => $checkedAt,
            'logs' => $logs,
            'vulnerability_count' => $vulnerabilityCount,
            'by_severity' => [
                'info' => $logs->where('severity', 'info')->count(),
                'warning' => $logs->where('severity', 'warning')->count(),
                'high' => $logs->where('severity', 'high')->count(),
                'critical' => $logs->where('severity', 'critical')->count(),
            ],
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function lookupDnsRecords(string $hostname, int $dnsType): array
    {
        $hostname = trim(strtolower($hostname));
        if ($hostname === '') {
            return [];
        }

        $pcntlEnabled = function_exists('pcntl_alarm') && function_exists('pcntl_signal') && function_exists('pcntl_async_signals');
        $previousAsyncSignals = null;
        $previousSignalHandler = null;

        set_error_handler(static function (int $severity, string $message) use ($hostname): never {
            throw new RuntimeException("DNS lookup failed for {$hostname}: {$message}");
        });

        try {
            if ($pcntlEnabled) {
                $previousAsyncSignals = pcntl_async_signals();
                $previousSignalHandler = pcntl_signal_get_handler(SIGALRM);
                pcntl_async_signals(true);
                pcntl_signal(SIGALRM, static function (): never {
                    throw new RuntimeException('DNS lookup timed out.');
                });
                pcntl_alarm(self::DNS_TIMEOUT_SECONDS);
            }

            $records = dns_get_record($hostname, $dnsType);

            return is_array($records) ? array_values($records) : [];
        } catch (Throwable $e) {
            Log::warning("DNS lookup error for {$hostname}: {$e->getMessage()}");

            return [];
        } finally {
            restore_error_handler();

            if ($pcntlEnabled) {
                pcntl_alarm(0);

                if ($previousSignalHandler !== null) {
                    pcntl_signal(SIGALRM, $previousSignalHandler);
                }

                if ($previousAsyncSignals !== null) {
                    pcntl_async_signals($previousAsyncSignals);
                }
            }
        }
    }

    private function evaluateAddressRecords(MonitoredDomain $monitoredDomain, string $recordType, array $records, Carbon $checkedAt): DnsSecurityLog
    {
        $currentValue = $this->normalizeAddressRecords($records);
        $expectedValue = $this->resolveExpectedValue($monitoredDomain, $recordType, $currentValue);

        if ($currentValue === '') {
            return $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: $recordType,
                expectedValue: $expectedValue,
                currentValue: '',
                severity: $expectedValue !== null ? 'high' : 'warning',
                status: 'missing',
                description: $expectedValue !== null
                    ? "Expected {$recordType} records were not returned by DNS."
                    : "No {$recordType} records were returned by DNS.",
                checkedAt: $checkedAt
            );
        }

        if ($expectedValue !== null && $expectedValue !== $currentValue) {
            return $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: $recordType,
                expectedValue: $expectedValue,
                currentValue: $currentValue,
                severity: 'warning',
                status: 'mismatch',
                description: "{$recordType} records changed from the expected baseline.",
                checkedAt: $checkedAt
            );
        }

        return $this->createSecureLog(
            monitoredDomain: $monitoredDomain,
            recordType: $recordType,
            expectedValue: $expectedValue ?? $currentValue,
            currentValue: $currentValue,
            description: "{$recordType} records match the current baseline.",
            checkedAt: $checkedAt
        );
    }

    private function evaluateMailExchangeRecords(MonitoredDomain $monitoredDomain, array $records, Carbon $checkedAt): DnsSecurityLog
    {
        $currentValue = $this->normalizeMxRecords($records);
        $expectedValue = $this->resolveExpectedValue($monitoredDomain, 'MX', $currentValue);

        if ($currentValue === '') {
            return $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'MX',
                expectedValue: $expectedValue,
                currentValue: '',
                severity: $expectedValue !== null ? 'high' : 'warning',
                status: 'missing',
                description: $expectedValue !== null
                    ? 'Expected MX records were not returned by DNS.'
                    : 'No MX records were returned by DNS.',
                checkedAt: $checkedAt
            );
        }

        if ($expectedValue !== null && $expectedValue !== $currentValue) {
            return $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'MX',
                expectedValue: $expectedValue,
                currentValue: $currentValue,
                severity: 'warning',
                status: 'mismatch',
                description: 'MX records changed from the expected baseline.',
                checkedAt: $checkedAt
            );
        }

        return $this->createSecureLog(
            monitoredDomain: $monitoredDomain,
            recordType: 'MX',
            expectedValue: $expectedValue ?? $currentValue,
            currentValue: $currentValue,
            description: 'MX records match the current baseline.',
            checkedAt: $checkedAt
        );
    }

    /**
     * @return \Illuminate\Support\Collection<int, \App\Models\DnsSecurityLog>
     */
    private function evaluateSpfRecords(MonitoredDomain $monitoredDomain, array $txtRecords, Carbon $checkedAt): Collection
    {
        $spfRecords = collect($txtRecords)
            ->map(fn (array $record): string => trim((string) ($record['txt'] ?? '')))
            ->filter(fn (string $value): bool => str_starts_with(strtolower($value), 'v=spf1'))
            ->values();

        if ($spfRecords->count() === 0) {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'SPF',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'SPF'),
                    currentValue: '',
                    severity: 'high',
                    status: 'missing',
                    description: 'No SPF policy was found in TXT records.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        if ($spfRecords->count() > 1) {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'SPF',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'SPF'),
                    currentValue: $spfRecords->implode(PHP_EOL),
                    severity: 'critical',
                    status: 'vulnerable',
                    description: 'Multiple SPF policies were found. RFC 7208 permits only one SPF record.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        $spfRecord = (string) $spfRecords->first();
        $severity = str_contains($spfRecord, '-all') || str_contains($spfRecord, '~all') ? 'info' : 'warning';
        $status = $severity === 'info' ? 'secure' : 'vulnerable';
        $description = $severity === 'info'
            ? 'A single SPF policy was found and appears syntactically valid.'
            : 'An SPF policy exists, but it does not contain a hard or soft enforcement qualifier.';

        $log = $status === 'secure'
            ? $this->createSecureLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'SPF',
                expectedValue: $this->resolveExpectedValue($monitoredDomain, 'SPF', $spfRecord) ?? $spfRecord,
                currentValue: $spfRecord,
                description: $description,
                checkedAt: $checkedAt
            )
            : $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'SPF',
                expectedValue: $this->resolveExpectedValue($monitoredDomain, 'SPF', $spfRecord),
                currentValue: $spfRecord,
                severity: $severity,
                status: $status,
                description: $description,
                checkedAt: $checkedAt
            );

        return collect([$log]);
    }

    /**
     * @return \Illuminate\Support\Collection<int, \App\Models\DnsSecurityLog>
     */
    private function evaluateDmarcRecords(MonitoredDomain $monitoredDomain, array $txtRecords, Carbon $checkedAt): Collection
    {
        $dmarcRecords = collect($txtRecords)
            ->map(fn (array $record): string => trim((string) ($record['txt'] ?? '')))
            ->filter(fn (string $value): bool => str_starts_with(strtolower($value), 'v=dmarc1'))
            ->values();

        if ($dmarcRecords->count() === 0) {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'DMARC',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DMARC'),
                    currentValue: '',
                    severity: 'high',
                    status: 'vulnerable',
                    description: 'No DMARC policy was found at the _dmarc subdomain.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        if ($dmarcRecords->count() > 1) {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'DMARC',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DMARC'),
                    currentValue: $dmarcRecords->implode(PHP_EOL),
                    severity: 'critical',
                    status: 'vulnerable',
                    description: 'Multiple DMARC policies were found. Only one DMARC record should exist.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        $dmarcRecord = (string) $dmarcRecords->first();
        $policy = $this->extractTaggedValue($dmarcRecord, 'p');

        if ($policy === null) {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'DMARC',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DMARC'),
                    currentValue: $dmarcRecord,
                    severity: 'high',
                    status: 'vulnerable',
                    description: 'A DMARC record exists, but the policy tag is missing or malformed.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        if ($policy === 'none') {
            return collect([
                $this->createLog(
                    monitoredDomain: $monitoredDomain,
                    recordType: 'DMARC',
                    expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DMARC', $dmarcRecord),
                    currentValue: $dmarcRecord,
                    severity: 'warning',
                    status: 'vulnerable',
                    description: 'The DMARC policy is set to p=none, which monitors failures but does not enforce protection.',
                    checkedAt: $checkedAt
                ),
            ]);
        }

        return collect([
            $this->createSecureLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'DMARC',
                expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DMARC', $dmarcRecord) ?? $dmarcRecord,
                currentValue: $dmarcRecord,
                description: "A DMARC policy was found with enforcement level p={$policy}.",
                checkedAt: $checkedAt
            ),
        ]);
    }

    private function evaluateDkimRecords(MonitoredDomain $monitoredDomain, Carbon $checkedAt): DnsSecurityLog
    {
        $selectorsFound = [];

        foreach (self::COMMON_DKIM_SELECTORS as $selector) {
            $fqdn = "{$selector}._domainkey.{$monitoredDomain->domain}";
            $records = $this->lookupDnsRecords($fqdn, DNS_TXT | DNS_CNAME);

            if (!empty($records)) {
                $selectorsFound[] = $selector;
            }
        }

        if ($selectorsFound === []) {
            return $this->createLog(
                monitoredDomain: $monitoredDomain,
                recordType: 'DKIM',
                expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DKIM'),
                currentValue: '',
                severity: 'warning',
                status: 'missing',
                description: 'No DKIM keys were found using common selectors. The domain may still use custom selectors.',
                checkedAt: $checkedAt
            );
        }

        $currentValue = implode(', ', $selectorsFound);

        return $this->createSecureLog(
            monitoredDomain: $monitoredDomain,
            recordType: 'DKIM',
            expectedValue: $this->resolveExpectedValue($monitoredDomain, 'DKIM', $currentValue) ?? $currentValue,
            currentValue: $currentValue,
            description: 'DKIM records were discovered on one or more common selectors.',
            checkedAt: $checkedAt
        );
    }

    private function normalizeAddressRecords(array $records): string
    {
        $values = collect($records)
            ->map(fn (array $record): string => trim((string) ($record['ip'] ?? '')))
            ->filter()
            ->unique()
            ->sort()
            ->values()
            ->all();

        return implode(', ', $values);
    }

    private function normalizeMxRecords(array $records): string
    {
        $values = collect($records)
            ->map(function (array $record): ?string {
                $target = trim((string) ($record['target'] ?? ''));
                if ($target === '') {
                    return null;
                }

                $priority = (int) ($record['pri'] ?? 0);

                return sprintf('%d %s', $priority, strtolower($target));
            })
            ->filter()
            ->sort()
            ->values()
            ->all();

        return implode(', ', $values);
    }

    private function extractTaggedValue(string $record, string $tag): ?string
    {
        if (!preg_match('/(?:^|;)\s*' . preg_quote($tag, '/') . '\s*=\s*([^;]+)/i', $record, $matches)) {
            return null;
        }

        $value = strtolower(trim($matches[1]));

        return $value !== '' ? $value : null;
    }

    private function resolveExpectedValue(MonitoredDomain $monitoredDomain, string $recordType, ?string $fallback = null): ?string
    {
        $expectedValue = $monitoredDomain->dnsSecurityLogs()
            ->where('record_type', $recordType)
            ->whereNotNull('expected_value')
            ->latest('id')
            ->value('expected_value');

        if (is_string($expectedValue) && trim($expectedValue) !== '') {
            return trim($expectedValue);
        }

        return $fallback !== null && trim($fallback) !== '' ? trim($fallback) : null;
    }

    private function createSecureLog(
        MonitoredDomain $monitoredDomain,
        string $recordType,
        ?string $expectedValue,
        string $currentValue,
        string $description,
        Carbon $checkedAt
    ): DnsSecurityLog {
        $this->resolveOpenIssues($monitoredDomain, $recordType, $checkedAt);

        return $this->createLog(
            monitoredDomain: $monitoredDomain,
            recordType: $recordType,
            expectedValue: $expectedValue,
            currentValue: $currentValue,
            severity: 'info',
            status: 'secure',
            description: $description,
            checkedAt: $checkedAt
        );
    }

    private function createLog(
        MonitoredDomain $monitoredDomain,
        string $recordType,
        ?string $expectedValue,
        string $currentValue,
        string $severity,
        string $status,
        string $description,
        Carbon $checkedAt
    ): DnsSecurityLog {
        return $monitoredDomain->dnsSecurityLogs()->create([
            'record_type' => $recordType,
            'expected_value' => $expectedValue,
            'current_value' => $currentValue,
            'severity' => $severity,
            'status' => $status,
            'description' => $description,
            'resolved_at' => $status === 'secure' ? $checkedAt : null,
        ]);
    }

    private function resolveOpenIssues(MonitoredDomain $monitoredDomain, string $recordType, Carbon $checkedAt): void
    {
        $monitoredDomain->dnsSecurityLogs()
            ->where('record_type', $recordType)
            ->whereNull('resolved_at')
            ->where('status', '!=', 'secure')
            ->update([
                'resolved_at' => $checkedAt,
            ]);
    }

    /**
     * @param \Illuminate\Support\Collection<int, \App\Models\DnsSecurityLog> $logs
     */
    private function dispatchDnsDriftAlerts(MonitoredDomain $monitoredDomain, Collection $logs): void
    {
        $logs
            ->filter(function (DnsSecurityLog $log): bool {
                if (!in_array($log->record_type, ['SPF', 'DMARC'], true)) {
                    return false;
                }

                return $log->status === 'missing' || $log->severity === 'critical';
            })
            ->each(function (DnsSecurityLog $log) use ($monitoredDomain): void {
                $previousLog = $monitoredDomain->dnsSecurityLogs()
                    ->where('record_type', $log->record_type)
                    ->where('id', '<', $log->id)
                    ->latest('id')
                    ->first();

                if ($previousLog === null || $previousLog->status !== 'secure') {
                    return;
                }

                $throttleKey = "alert_dns_drift_{$monitoredDomain->id}_{$log->record_type}";

                if (!$this->shouldDispatchAlert($throttleKey, 86400)) {
                    return;
                }

                $severity = $log->severity === 'critical' ? 'CRITICAL' : 'HIGH';

                $this->securityAlertDispatcher->dispatch(
                    $monitoredDomain->company,
                    new SecurityAlertNotification(
                        alertType: 'dns_drift',
                        domainName: $monitoredDomain->domain,
                        severity: $severity,
                        message: "{$log->record_type} posture regressed from a previously secure state. {$log->description}"
                    )
                );
            });
    }

    private function shouldDispatchAlert(string $cacheKey, int $ttlSeconds): bool
    {
        $status = Cache::remember($cacheKey, $ttlSeconds, static fn (): string => 'ready');

        if ($status !== 'ready') {
            return false;
        }

        Cache::put($cacheKey, 'sent', $ttlSeconds);

        return true;
    }
}
