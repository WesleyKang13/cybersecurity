<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\AttackSpikeAlert;
use App\Models\Company;
use App\Models\MonitoredDomain;
use App\Notifications\SecurityAlertNotification;
use App\Support\ThreatEventPresentation;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

final class AttackSpikeAlertService
{
    private const COOLDOWN_SECONDS = 1800;

    private const DELIVERY_LOCK_SECONDS = 60;

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

        $windowMinutes = max(1, (int) config('security.alerts.attack_spike.window_minutes', 10));
        $highThreshold = max(1, (int) config('security.alerts.attack_spike.high_threshold', 10));
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

        $newAlert = null;

        if ($eventsInWindow >= $highThreshold) {
            $outcomes = $eventsInWindowQuery
                ->get()
                ->groupBy(fn ($event): string => ThreatEventPresentation::actionOutcome($event->action_taken))
                ->map(fn ($events, string $outcome): int => $events->count())
                ->all();

            $newAlert = [
                'severity' => $eventsInWindow >= $criticalThreshold ? 'CRITICAL' : 'HIGH',
                'detected_at' => $detectedAt,
                'events_in_window' => $eventsInWindow,
                'monitoring_window_minutes' => $windowMinutes,
                'high_threshold' => $highThreshold,
                'critical_threshold' => $criticalThreshold,
                'new_events_added_during_latest_sync' => max(0, $newEventsAddedDuringLatestSync),
                'outcomes' => $outcomes,
            ];
        }

        $claim = $this->claimPendingAlert($company, $domain, $newAlert);

        if ($claim === null) {
            return;
        }

        /** @var AttackSpikeAlert $alert */
        $alert = $claim['alert'];
        $lockToken = $claim['lock_token'];

        try {
            $delivery = $this->securityAlertDispatcher->dispatchAttackSpike(
                $company,
                $this->notificationFor($domain, $alert),
                $alert->delivered_channels ?? []
            );
        } catch (\Throwable $exception) {
            Log::warning('Attack spike alert delivery failed.', [
                'company_id' => $company->id,
                'domain_id' => $domain->id,
                'attack_spike_alert_id' => $alert->id,
                'exception_class' => $exception::class,
            ]);

            $delivery = ['delivered' => [], 'failed' => ['dispatcher']];
        }

        $this->recordDeliveryAttempt($alert, $lockToken, $delivery);
    }

    /**
     * @param  array{severity: string, detected_at: CarbonImmutable, events_in_window: int, monitoring_window_minutes: int, high_threshold: int, critical_threshold: int, new_events_added_during_latest_sync: int, outcomes: array<string, int>}|null  $newAlert
     * @return array{alert: AttackSpikeAlert, lock_token: string}|null
     */
    private function claimPendingAlert(Company $company, MonitoredDomain $domain, ?array $newAlert): ?array
    {
        return DB::transaction(function () use ($company, $domain, $newAlert): ?array {
            $lockedDomain = MonitoredDomain::query()
                ->whereKey($domain->id)
                ->where('company_id', $company->id)
                ->lockForUpdate()
                ->first();

            if ($lockedDomain === null) {
                return null;
            }

            $now = CarbonImmutable::now('UTC');
            $pendingAlerts = AttackSpikeAlert::query()
                ->where('company_id', $company->id)
                ->where('monitored_domain_id', $domain->id)
                ->where('status', AttackSpikeAlert::STATUS_PENDING);

            if ($newAlert !== null) {
                $pendingForSeverity = (clone $pendingAlerts)
                    ->where('severity', $newAlert['severity'])
                    ->orderBy('id')
                    ->first();

                if ($pendingForSeverity !== null) {
                    return $this->claimIfAvailable($pendingForSeverity, $now);
                }

                if (! $this->isCoolingDown($company, $domain, $newAlert['severity'], $now)) {
                    $pending = AttackSpikeAlert::create([
                        'company_id' => $company->id,
                        'monitored_domain_id' => $domain->id,
                        'severity' => $newAlert['severity'],
                        'status' => AttackSpikeAlert::STATUS_PENDING,
                        'detected_at' => $newAlert['detected_at'],
                        'events_in_window' => $newAlert['events_in_window'],
                        'monitoring_window_minutes' => $newAlert['monitoring_window_minutes'],
                        'high_threshold' => $newAlert['high_threshold'],
                        'critical_threshold' => $newAlert['critical_threshold'],
                        'new_events_added_during_latest_sync' => $newAlert['new_events_added_during_latest_sync'],
                        'outcomes' => $newAlert['outcomes'],
                        'delivered_channels' => [],
                    ]);

                    return $this->claimAlert($pending, $now);
                }
            }

            $pending = $pendingAlerts->orderBy('id')->first();

            if ($pending === null) {
                return null;
            }

            return $this->claimIfAvailable($pending, $now);
        });
    }

    /**
     * @return array{alert: AttackSpikeAlert, lock_token: string}|null
     */
    private function claimIfAvailable(AttackSpikeAlert $alert, CarbonImmutable $now): ?array
    {
        if ($alert->delivery_lock_expires_at?->isAfter($now)) {
            return null;
        }

        return $this->claimAlert($alert, $now);
    }

    /**
     * @return array{alert: AttackSpikeAlert, lock_token: string}
     */
    private function claimAlert(AttackSpikeAlert $alert, CarbonImmutable $now): array
    {
        $lockToken = (string) Str::uuid();
        $alert->forceFill([
            'delivery_lock_token' => $lockToken,
            'delivery_lock_expires_at' => $now->addSeconds(self::DELIVERY_LOCK_SECONDS),
            'last_attempt_at' => $now,
        ])->save();

        return ['alert' => $alert, 'lock_token' => $lockToken];
    }

    /**
     * @param  array{delivered: list<string>, failed: list<string>}  $delivery
     */
    private function recordDeliveryAttempt(AttackSpikeAlert $alert, string $lockToken, array $delivery): void
    {
        DB::transaction(function () use ($alert, $lockToken, $delivery): void {
            $lockedAlert = AttackSpikeAlert::query()
                ->whereKey($alert->id)
                ->where('status', AttackSpikeAlert::STATUS_PENDING)
                ->lockForUpdate()
                ->first();

            if ($lockedAlert === null || ! hash_equals((string) $lockedAlert->delivery_lock_token, $lockToken)) {
                return;
            }

            $deliveredChannels = array_values(array_unique(array_merge(
                $lockedAlert->delivered_channels ?? [],
                $delivery['delivered']
            )));
            $now = CarbonImmutable::now('UTC');
            $attributes = [
                'delivered_channels' => $deliveredChannels,
                'delivery_lock_token' => null,
                'delivery_lock_expires_at' => null,
                'last_attempt_at' => $now,
            ];

            if ($delivery['failed'] === []) {
                $attributes['status'] = AttackSpikeAlert::STATUS_DELIVERED;
                $attributes['delivered_at'] = $now;

                Cache::put($this->cooldownCacheKey($lockedAlert), 'sent', self::COOLDOWN_SECONDS);
            }

            $lockedAlert->forceFill($attributes)->save();
        });
    }

    private function isCoolingDown(
        Company $company,
        MonitoredDomain $domain,
        string $severity,
        CarbonImmutable $now
    ): bool {
        $cacheKey = $this->cooldownCacheKey($company->id, $domain->id, $severity);

        if (Cache::has($cacheKey)) {
            return true;
        }

        return AttackSpikeAlert::query()
            ->where('company_id', $company->id)
            ->where('monitored_domain_id', $domain->id)
            ->where('severity', $severity)
            ->where('status', AttackSpikeAlert::STATUS_DELIVERED)
            ->where('delivered_at', '>', $now->subSeconds(self::COOLDOWN_SECONDS))
            ->exists();
    }

    private function cooldownCacheKey(AttackSpikeAlert|int $alertOrCompanyId, ?int $domainId = null, ?string $severity = null): string
    {
        if ($alertOrCompanyId instanceof AttackSpikeAlert) {
            return "security_alert:attack_spike:{$alertOrCompanyId->company_id}:{$alertOrCompanyId->monitored_domain_id}:{$alertOrCompanyId->severity}";
        }

        return "security_alert:attack_spike:{$alertOrCompanyId}:{$domainId}:{$severity}";
    }

    private function notificationFor(MonitoredDomain $domain, AttackSpikeAlert $alert): SecurityAlertNotification
    {
        $outcomes = is_array($alert->outcomes) ? $alert->outcomes : [];
        $outcomeSummary = $this->formatOutcomeSummary($outcomes);

        return new SecurityAlertNotification(
            alertType: 'attack_spike',
            domainName: $domain->domain,
            severity: $alert->severity,
            message: "{$alert->events_in_window} attempted security events were observed during the last {$alert->monitoring_window_minutes} minutes. Reported outcomes: {$outcomeSummary}.",
            detectedAt: $alert->detected_at,
            details: [
                'events_in_window' => $alert->events_in_window,
                'monitoring_window_minutes' => $alert->monitoring_window_minutes,
                'high_threshold' => $alert->high_threshold,
                'critical_threshold' => $alert->critical_threshold,
                'new_events_added_during_latest_sync' => $alert->new_events_added_during_latest_sync,
                'outcomes' => $outcomes,
            ]
        );
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
