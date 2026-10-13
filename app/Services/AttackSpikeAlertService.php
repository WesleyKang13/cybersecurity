<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Notifications\SecurityAlertNotification;
use App\Support\ThreatEventPresentation;
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

        $eventsInWindowQuery = $domain->securityThreatLogs()
            ->whereBetween('detected_at', [$windowStart, $detectedAt])
            ->select(['action_taken']);
        $eventsInWindow = (clone $eventsInWindowQuery)->count();

        if ($eventsInWindow < $highThreshold) {
            return;
        }

        $severity = $eventsInWindow >= $criticalThreshold ? 'CRITICAL' : 'HIGH';
        $cacheKey = "security_alert:attack_spike:{$company->id}:{$domain->id}:{$severity}";

        if (! Cache::add($cacheKey, 'sent', self::COOLDOWN_SECONDS)) {
            return;
        }

        $outcomes = $eventsInWindowQuery
            ->get()
            ->groupBy(fn ($event): string => ThreatEventPresentation::actionOutcome($event->action_taken))
            ->map(fn ($events, string $outcome): int => $events->count())
            ->all();
        $outcomeSummary = $this->formatOutcomeSummary($outcomes);

        try {
            $this->securityAlertDispatcher->dispatch(
                $company,
                new SecurityAlertNotification(
                    alertType: 'attack_spike',
                    domainName: $domain->domain,
                    severity: $severity,
                    message: "{$eventsInWindow} attempted security events were observed during the last {$windowMinutes} minutes. Reported outcomes: {$outcomeSummary}.",
                    detectedAt: $detectedAt,
                    details: [
                        'events_in_window' => $eventsInWindow,
                        'monitoring_window_minutes' => $windowMinutes,
                        'high_threshold' => $highThreshold,
                        'critical_threshold' => $criticalThreshold,
                        'new_events_added_during_latest_sync' => max(0, $newEventsAddedDuringLatestSync),
                        'outcomes' => $outcomes,
                    ]
                )
            );
        } catch (\Throwable $exception) {
            Log::warning('Attack spike alert delivery failed after cooldown claim.', [
                'company_id' => $company->id,
                'domain_id' => $domain->id,
                'exception_class' => $exception::class,
            ]);
        }
    }

    /**
     * @param  array<string, int>  $outcomes
     */
    private function formatOutcomeSummary(array $outcomes): string
    {
        $parts = [];

        foreach (['blocked', 'challenged', 'logged', 'allowed', 'reported'] as $outcome) {
            if (! isset($outcomes[$outcome])) {
                continue;
            }

            $parts[] = "{$outcomes[$outcome]} {$outcome}";
        }

        return $parts !== [] ? implode(', ', $parts) : 'outcome not reported';
    }
}
