<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Notifications\SecurityAlertNotification;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

final class AttackSpikeAlertService
{
    private const COOLDOWN_SECONDS = 1800;

    public function __construct(
        private readonly SecurityAlertDispatcher $securityAlertDispatcher
    ) {}

    public function evaluate(MonitoredDomain $domain, int $newEventsAddedDuringLatestSync = 0): void
    {
        $company = $domain->company;

        if (! $company instanceof Company) {
            Log::warning("Attack spike evaluation skipped for domain {$domain->id}: company ownership is missing.");

            return;
        }

        if ($company->status !== Company::STATUS_ACTIVE) {
            return;
        }

        $windowMinutes = max(
            1,
            (int) config('security.alerts.attack_spike.window_minutes', 10)
        );
        $highThreshold = max(
            1,
            (int) config('security.alerts.attack_spike.high_threshold', 10)
        );
        $criticalThreshold = max(
            $highThreshold,
            (int) config('security.alerts.attack_spike.critical_threshold', 25)
        );
        $detectedAt = CarbonImmutable::now('UTC');
        $windowStart = $detectedAt->subMinutes($windowMinutes);

        $eventsInWindow = $domain->securityThreatLogs()
            ->whereBetween('detected_at', [$windowStart, $detectedAt])
            ->count();

        if ($eventsInWindow < $highThreshold) {
            return;
        }

        $cacheKey = "security_alert:attack_spike:{$company->id}:{$domain->id}";
        $status = Cache::remember(
            $cacheKey,
            self::COOLDOWN_SECONDS,
            static fn (): string => 'ready'
        );

        if ($status !== 'ready') {
            return;
        }

        Cache::put($cacheKey, 'sent', self::COOLDOWN_SECONDS);

        $severity = $eventsInWindow >= $criticalThreshold ? 'CRITICAL' : 'HIGH';

        $this->securityAlertDispatcher->dispatch(
            $company,
            new SecurityAlertNotification(
                alertType: 'attack_spike',
                domainName: $domain->domain,
                severity: $severity,
                message: "{$eventsInWindow} security events were detected during the last {$windowMinutes} minutes.",
                detectedAt: $detectedAt,
                details: [
                    'events_in_window' => $eventsInWindow,
                    'monitoring_window_minutes' => $windowMinutes,
                    'high_threshold' => $highThreshold,
                    'critical_threshold' => $criticalThreshold,
                    'new_events_added_during_latest_sync' => max(0, $newEventsAddedDuringLatestSync),
                ]
            )
        );
    }
}
