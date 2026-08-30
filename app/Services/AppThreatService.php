<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\BlockedIp;
use App\Models\MonitoredDomain;
use App\Notifications\SecurityAlertNotification;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Cache;

class AppThreatService
{
    private const THREAT_COUNT_WINDOW_SECONDS = 60;

    public function __construct(
        private readonly SecurityAlertDispatcher $securityAlertDispatcher
    ) {}

    /**
     * @param list<array{
     *     attacker_ip: string,
     *     targeted_path: string,
     *     user_agent: string,
     *     timestamp: string,
     *     event_type?: string|null,
     *     severity?: string|null,
     *     reason?: string|null,
     *     metadata?: array<array-key, mixed>|null
     * }> $events
     * @return array{events_synced: int, new_events_count: int}
     */
    public function ingestThreatEvents(MonitoredDomain $domain, array $events): array
    {
        $synced = 0;
        $newEventsCount = 0;

        foreach ($events as $event) {
            $attackerIp = trim($event['attacker_ip']);
            $detectedAt = CarbonImmutable::parse($event['timestamp'])->toDateTimeString();
            $pathTargeted = trim($event['targeted_path']);

            $attributes = [
                'country' => null,
                'user_agent' => trim($event['user_agent']) !== '' ? trim($event['user_agent']) : null,
                'action_taken' => 'log',
                'threat_source' => 'app_middleware',
            ];

            foreach (['event_type', 'severity', 'reason', 'metadata'] as $optionalField) {
                if (array_key_exists($optionalField, $event) && $event[$optionalField] !== null) {
                    $attributes[$optionalField] = is_string($event[$optionalField])
                        ? trim($event[$optionalField])
                        : $event[$optionalField];
                }
            }

            $threatLog = $domain->securityThreatLogs()->updateOrCreate(
                [
                    'monitored_domain_id' => $domain->id,
                    'attacker_ip' => $attackerIp,
                    'path_targeted' => $pathTargeted !== '' ? $pathTargeted : null,
                    'detected_at' => $detectedAt,
                ],
                $attributes
            );

            $synced++;

            if ($threatLog->wasRecentlyCreated) {
                $newEventsCount++;
            }

            $this->handleAutoBan($domain, $attackerIp);
        }

        return [
            'events_synced' => $synced,
            'new_events_count' => $newEventsCount,
        ];
    }

    private function handleAutoBan(MonitoredDomain $domain, string $attackerIp): void
    {
        $cacheKey = "threat_count_{$attackerIp}_{$domain->id}";

        if (! Cache::has($cacheKey)) {
            Cache::put($cacheKey, 0, now()->addSeconds(self::THREAT_COUNT_WINDOW_SECONDS));
        }

        $count = (int) Cache::increment($cacheKey);
        Cache::put($cacheKey, $count, now()->addSeconds(self::THREAT_COUNT_WINDOW_SECONDS));

        $threshold = max(1, (int) ($domain->auto_ban_threshold ?? 10));

        if ($count <= $threshold) {
            return;
        }

        $blockedIp = BlockedIp::query()
            ->where('ip', $attackerIp)
            ->first();

        if ($blockedIp !== null) {
            return;
        }

        BlockedIp::create([
            'ip' => $attackerIp,
            'is_global' => true,
            'reason' => 'Auto-banned: exceeded threat threshold',
        ]);

        $this->securityAlertDispatcher->dispatch(
            $domain->company,
            new SecurityAlertNotification(
                alertType: 'auto_ban',
                domainName: $domain->domain,
                severity: 'HIGH',
                message: "IP {$attackerIp} has been auto-banned after exceeding the threat threshold of {$threshold} reports within 60 seconds."
            )
        );
    }
}
