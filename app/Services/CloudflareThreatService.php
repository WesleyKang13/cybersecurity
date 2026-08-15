<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Notifications\SecurityAlertNotification;
use Carbon\CarbonImmutable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class CloudflareThreatService
{
    private const API_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql';
    private const TIMEOUT_SECONDS = 5;
    private const EVENT_LIMIT = 100;
    private const MIDDLEWARE_LOOKBACK_HOURS = 24;
    private const BLOCKED_IP_CACHE_TTL_SECONDS = 600;

    public function __construct(
        private readonly SecurityAlertDispatcher $securityAlertDispatcher
    ) {
    }

    /**
     * @return array{domains_processed: int, events_synced: int, failed: int, skipped: int}
     */
    public function syncOwnedDomains(): array
    {
        $token = (string) config('services.cloudflare.api_token', '');

        $domains = MonitoredDomain::query()
            ->where('is_active', true)
            ->where('is_owned', true)
            ->orderBy('domain')
            ->get();

        $summary = [
            'domains_processed' => 0,
            'events_synced' => 0,
            'failed' => 0,
            'skipped' => 0,
        ];

        foreach ($domains as $domain) {
            try {
                $summary['domains_processed']++;

                if ($this->shouldProcessAsCloudflare($domain)) {
                    $zoneId = trim((string) $domain->cloudflare_zone_id);

                    if ($token === '') {
                        $summary['skipped']++;
                        Log::warning("Cloudflare threat sync skipped for {$domain->domain}: CLOUDFLARE_API_TOKEN is not configured.");

                        continue;
                    }

                    if ($zoneId === '') {
                        $summary['skipped']++;
                        Log::warning("Cloudflare threat sync skipped for {$domain->domain}: Cloudflare Zone ID is missing.");

                        continue;
                    }

                    Log::info("Processing Tier 2 (Cloudflare) threats for: {$domain->domain}");
                    $result = $this->syncDomainThreats($domain, $zoneId, $token);
                } elseif ($domain->infrastructure_type === 'app_middleware') {
                    Log::info("Processing Tier 3 (Middleware) telemetry for: {$domain->domain}");
                    $result = $this->processMiddlewareTelemetry($domain);
                } else {
                    $summary['skipped']++;

                    continue;
                }

                $summary['events_synced'] += $result['events_synced'];

                $this->dispatchAttackSpikeAlert($domain, $result['new_events_count']);
            } catch (ConnectionException|RequestException $e) {
                $summary['failed']++;
                Log::warning("Cloudflare threat sync failed for {$domain->domain}: {$e->getMessage()}");
            } catch (\Throwable $e) {
                $summary['failed']++;
                Log::error("Unexpected Cloudflare threat sync failure for {$domain->domain}: {$e->getMessage()}");
            }
        }

        return $summary;
    }

    private function shouldProcessAsCloudflare(MonitoredDomain $domain): bool
    {
        return $domain->infrastructure_type === 'cloudflare'
            || filled($domain->cloudflare_zone_id);
    }

    /**
     * @return array{events_synced: int, new_events_count: int}
     */
    private function syncDomainThreats(MonitoredDomain $domain, string $zoneId, string $token): array
    {
        $startTime = now()->subHours(2)->toIso8601String();
        $endTime = now()->toIso8601String();

        $response = Http::withToken($token)
            ->acceptJson()
            ->timeout(self::TIMEOUT_SECONDS)
            ->connectTimeout(self::TIMEOUT_SECONDS)
            ->post(self::API_ENDPOINT, [
                'query' => $this->buildQuery(),
                'variables' => [
                    'zoneTag' => $zoneId,
                    'since' => $startTime,
                    'until' => $endTime,
                    'limit' => self::EVENT_LIMIT,
                ],
            ])
            ->throw();

        $payload = $response->json();

        if (!empty($payload['errors']) && is_array($payload['errors'])) {
            $errorMessage = collect($payload['errors'])
                ->map(static fn (mixed $error): string => (string) data_get($error, 'message', 'Unknown Cloudflare GraphQL error'))
                ->implode('; ');

            throw new RuntimeException("Cloudflare GraphQL errors: {$errorMessage}");
        }

        /** @var array<int, array<string, mixed>> $events */
        $events = data_get($payload, 'data.viewer.zones.0.firewallEventsAdaptive', []);

        return $this->storeEvents($domain, collect($events));
    }

    private function buildQuery(): string
    {
        return <<<'GRAPHQL'
query GetFirewallEvents($zoneTag: String!, $since: Time!, $until: Time!, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        limit: $limit
        orderBy: [datetime_DESC]
        filter: { datetime_geq: $since, datetime_leq: $until }
      ) {
        clientIP
        clientCountryName
        clientRequestPath
        action
        source
        datetime
      }
    }
  }
}
GRAPHQL;
    }

    /**
     * @param \Illuminate\Support\Collection<int, array<string, mixed>> $events
     */
    /**
     * @return array{events_synced: int, new_events_count: int}
     */
    private function storeEvents(MonitoredDomain $domain, Collection $events): array
    {
        $synced = 0;
        $newEventsCount = 0;

        foreach ($events as $event) {
            $attackerIp = trim((string) ($event['clientIP'] ?? ''));
            $detectedAtRaw = $event['datetime'] ?? null;

            if ($attackerIp === '' || !is_string($detectedAtRaw) || trim($detectedAtRaw) === '') {
                continue;
            }

            $detectedAt = CarbonImmutable::parse($detectedAtRaw)->toDateTimeString();
            $pathTargeted = $event['clientRequestPath'] ?? null;
            $pathTargeted = is_string($pathTargeted) && trim($pathTargeted) !== ''
                ? trim($pathTargeted)
                : null;

            $threatLog = $domain->securityThreatLogs()->updateOrCreate(
                [
                    'monitored_domain_id' => $domain->id,
                    'attacker_ip' => $attackerIp,
                    'path_targeted' => $pathTargeted,
                    'detected_at' => $detectedAt,
                ],
                [
                    'country' => $this->nullableString($event['clientCountryName'] ?? null),
                    'action_taken' => $this->nullableString($event['action'] ?? null) ?? 'log',
                    'threat_source' => $this->nullableString($event['source'] ?? null),
                ]
            );

            $synced++;

            if ($threatLog->wasRecentlyCreated) {
                $newEventsCount++;
            }
        }

        return [
            'events_synced' => $synced,
            'new_events_count' => $newEventsCount,
        ];
    }

    /**
     * @return array{events_synced: int, new_events_count: int}
     */
    private function processMiddlewareTelemetry(MonitoredDomain $domain): array
    {
        $since = $this->resolveMiddlewareSyncStart();
        $baseQuery = $domain->securityThreatLogs()
            ->where('threat_source', 'app_middleware');

        $newEventsCount = (clone $baseQuery)
            ->where('created_at', '>=', $since)
            ->count();

        $topTargetedPaths = (clone $baseQuery)
            ->selectRaw('path_targeted, COUNT(*) as event_count')
            ->whereNotNull('path_targeted')
            ->where('path_targeted', '!=', '')
            ->groupBy('path_targeted')
            ->orderByDesc('event_count')
            ->limit(5)
            ->get()
            ->map(static function (SecurityThreatLog $log): array {
                return [
                    'path_targeted' => $log->path_targeted,
                    'count' => (int) $log->event_count,
                ];
            })
            ->values()
            ->all();

        $topAttackerIps = (clone $baseQuery)
            ->selectRaw('attacker_ip, COUNT(*) as event_count')
            ->whereNotNull('attacker_ip')
            ->where('attacker_ip', '!=', '')
            ->groupBy('attacker_ip')
            ->orderByDesc('event_count')
            ->limit(10)
            ->get()
            ->map(static function (SecurityThreatLog $log): array {
                return [
                    'attacker_ip' => $log->attacker_ip,
                    'count' => (int) $log->event_count,
                ];
            })
            ->values()
            ->all();

        $blockedIps = (clone $baseQuery)
            ->where('action_taken', 'block')
            ->distinct()
            ->orderBy('attacker_ip')
            ->pluck('attacker_ip')
            ->filter(static fn (mixed $ip): bool => is_string($ip) && trim($ip) !== '')
            ->values()
            ->all();

        Cache::put(
            "telemetry_blocked_ips:{$domain->id}",
            $blockedIps,
            now()->addSeconds(self::BLOCKED_IP_CACHE_TTL_SECONDS)
        );

        Cache::put(
            "middleware_threat_summary:{$domain->id}",
            [
                'aggregated_at' => now()->toIso8601String(),
                'new_events_count' => $newEventsCount,
                'top_targeted_paths' => $topTargetedPaths,
                'top_attacker_ips' => $topAttackerIps,
                'blocked_ips_count' => count($blockedIps),
            ],
            now()->addHours(1)
        );

        return [
            'events_synced' => $newEventsCount,
            'new_events_count' => $newEventsCount,
        ];
    }

    private function resolveMiddlewareSyncStart(): Carbon
    {
        $lastSynced = Cache::get('threats_last_synced');

        if ($lastSynced instanceof Carbon) {
            return $lastSynced;
        }

        if ($lastSynced instanceof \DateTimeInterface) {
            return Carbon::instance(\DateTimeImmutable::createFromInterface($lastSynced));
        }

        return now()->subHours(self::MIDDLEWARE_LOOKBACK_HOURS);
    }

    private function nullableString(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $normalized = trim($value);

        return $normalized !== '' ? $normalized : null;
    }

    private function dispatchAttackSpikeAlert(MonitoredDomain $domain, int $newEventsCount): void
    {
        if ($newEventsCount < 10) {
            return;
        }

        $cacheKey = "alert_spike_{$domain->id}";
        $status = Cache::remember($cacheKey, 1800, static fn (): string => 'ready');

        if ($status !== 'ready') {
            return;
        }

        Cache::put($cacheKey, 'sent', 1800);

        $severity = $newEventsCount >= 25 ? 'CRITICAL' : 'HIGH';

        $this->securityAlertDispatcher->dispatch(
            new SecurityAlertNotification(
                alertType: 'attack_spike',
                domainName: $domain->domain,
                severity: $severity,
                message: "Cloudflare synced {$newEventsCount} new firewall event(s) for this domain in the latest batch. Review recent attacker IPs and mitigation rules."
            )
        );
    }
}
