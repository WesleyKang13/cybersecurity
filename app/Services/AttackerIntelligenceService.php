<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\BlockedIp;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Support\ThreatEventPresentation;
use Carbon\Carbon;
use Illuminate\Support\Collection;

class AttackerIntelligenceService
{
    public function __construct(
        private readonly IpIntelligenceService $ipIntelligenceService,
        private readonly CloudflareIpBlockService $cloudflareIpBlockService,
        private readonly ThreatClassificationService $threatClassificationService,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function investigate(string $ipAddress): array
    {
        return array_merge(
            $this->ipIntelligenceService->lookup($ipAddress),
            [
                'observations' => $this->observationsFor($ipAddress),
                'block_status' => $this->blockStatusFor($ipAddress),
            ]
        );
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function topAttackers(int $limit = 10): array
    {
        $attackers = SecurityThreatLog::query()
            ->select('attacker_ip')
            ->selectRaw('MAX(country) as country')
            ->selectRaw('COUNT(*) as total_events')
            ->selectRaw('COUNT(DISTINCT monitored_domain_id) as applications_targeted')
            ->selectRaw('MAX(detected_at) as most_recent_event')
            ->whereNotNull('attacker_ip')
            ->where('attacker_ip', '!=', '')
            ->groupBy('attacker_ip')
            ->orderByDesc('total_events')
            ->orderByDesc('most_recent_event')
            ->limit($limit)
            ->get();

        $blocksByIp = BlockedIp::query()
            ->whereIn('ip', $attackers->pluck('attacker_ip'))
            ->get()
            ->groupBy('ip');

        return $attackers
            ->map(function (SecurityThreatLog $attacker) use ($blocksByIp): array {
                /** @var Collection<int, BlockedIp> $blocks */
                $blocks = $blocksByIp->get($attacker->attacker_ip, collect());

                return [
                    'attacker_ip' => $attacker->attacker_ip,
                    'country' => $attacker->country,
                    'total_events' => (int) $attacker->total_events,
                    'applications_targeted' => (int) $attacker->applications_targeted,
                    'most_recent_event' => $attacker->most_recent_event
                        ? Carbon::parse($attacker->most_recent_event)->toIso8601String()
                        : null,
                    'tier_3_status' => $this->tier3BlockClassification($blocks),
                ];
            })
            ->values()
            ->all();
    }

    /**
     * @return array<string, mixed>
     */
    private function observationsFor(string $ipAddress): array
    {
        $events = SecurityThreatLog::query()
            ->with('monitoredDomain:id,domain')
            ->where('attacker_ip', $ipAddress)
            ->orderBy('detected_at')
            ->get();

        return [
            'total_events' => $events->count(),
            'first_seen' => $events->first()?->detected_at?->toIso8601String(),
            'last_seen' => $events->last()?->detected_at?->toIso8601String(),
            'applications_targeted' => $events->pluck('monitored_domain_id')->unique()->count(),
            'threat_sources' => $this->valueBreakdown($events, 'threat_source'),
            'top_applications' => $events
                ->groupBy('monitored_domain_id')
                ->map(function (Collection $domainEvents): array {
                    $domain = $domainEvents->first()?->monitoredDomain;

                    return [
                        'domain_id' => $domain?->id,
                        'domain' => $domain?->domain ?? 'Unknown application',
                        'count' => $domainEvents->count(),
                    ];
                })
                ->sort(fn (array $left, array $right): int => $right['count'] <=> $left['count']
                    ?: strcmp($left['domain'], $right['domain']))
                ->values()
                ->all(),
            'top_targeted_paths' => $events
                ->filter(fn (SecurityThreatLog $event): bool => filled($event->path_targeted))
                ->groupBy('path_targeted')
                ->map(fn (Collection $pathEvents, string $path): array => [
                    'path' => $path,
                    'count' => $pathEvents->count(),
                ])
                ->sort(fn (array $left, array $right): int => $right['count'] <=> $left['count']
                    ?: strcmp($left['path'], $right['path']))
                ->values()
                ->all(),
            'threat_types' => $this->valueBreakdown($events, 'event_type'),
            'severities' => $this->valueBreakdown($events, 'severity'),
            'actions_taken' => $this->valueBreakdown($events, 'action_taken'),
            'recent_activity' => $events
                ->sortByDesc('detected_at')
                ->take(10)
                ->map(function (SecurityThreatLog $event): array {
                    $derivedClassification = blank($event->event_type)
                        ? $this->threatClassificationService->classifyFromPath($event->path_targeted)
                        : null;

                    return [
                        'id' => $event->id,
                        'detected_at' => $event->detected_at?->toIso8601String(),
                        'domain' => $event->monitoredDomain?->domain ?? 'Unknown application',
                        'path_targeted' => $event->path_targeted,
                        'event_type' => $event->event_type ?? $derivedClassification['event_type'] ?? null,
                        'severity' => $event->severity ?? $derivedClassification['severity'] ?? null,
                        'reason' => $event->reason ?? $derivedClassification['reason'] ?? null,
                        'action_taken' => $event->action_taken,
                        'action_label' => ThreatEventPresentation::actionLabel($event->action_taken),
                        'action_outcome' => ThreatEventPresentation::actionOutcome($event->action_taken),
                        'threat_source' => $event->threat_source,
                        'source_label' => ThreatEventPresentation::sourceLabel($event->threat_source),
                        'source_kind' => ThreatEventPresentation::sourceKind($event->threat_source),
                    ];
                })
                ->values()
                ->all(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function blockStatusFor(string $ipAddress): array
    {
        $blocks = BlockedIp::query()
            ->with('monitoredDomain:id,domain')
            ->where('ip', $ipAddress)
            ->get();

        $cloudflareStatus = $this->cloudflareIpAccessRuleStatus($ipAddress);

        return [
            'classification' => $this->overallBlockClassification($blocks, $cloudflareStatus),
            'verified_locations' => $this->verifiedBlockLocations($blocks, $cloudflareStatus),
            'tier_3' => [
                'classification' => $this->tier3BlockClassification($blocks),
                'global_block_list_entry' => $blocks->contains('is_global', true),
                'domain_block_list_entries' => $blocks
                    ->where('is_global', false)
                    ->map(fn (BlockedIp $block): array => [
                        'domain_id' => $block->monitored_domain_id,
                        'domain' => $block->monitoredDomain?->domain ?? 'Unknown domain',
                    ])
                    ->values()
                    ->all(),
                'enforcement_note' => 'Tier 3 applications retrieve this block list and enforce it locally; the platform does not confirm inline blocking by each client.',
            ],
            'tier_2' => $cloudflareStatus,
        ];
    }

    /**
     * @param  Collection<int, SecurityThreatLog>  $events
     * @return array<int, array{value: string, count: int}>
     */
    private function valueBreakdown(Collection $events, string $attribute): array
    {
        return $events
            ->groupBy(function (SecurityThreatLog $event) use ($attribute): string {
                $value = $event->getAttribute($attribute);

                return is_string($value) && trim($value) !== '' ? trim($value) : 'unclassified';
            })
            ->map(fn (Collection $matchingEvents, string $value): array => [
                'value' => $value,
                'count' => $matchingEvents->count(),
            ])
            ->sort(fn (array $left, array $right): int => $right['count'] <=> $left['count']
                ?: strcmp($left['value'], $right['value']))
            ->values()
            ->all();
    }

    /**
     * @param  Collection<int, BlockedIp>  $blocks
     */
    private function tier3BlockClassification(Collection $blocks): string
    {
        if ($blocks->contains('is_global', true)) {
            return 'global_block_list_entry';
        }

        if ($blocks->contains('is_global', false)) {
            return 'domain_block_list_entry';
        }

        return 'not_listed';
    }

    /**
     * @return array{
     *     status: string,
     *     checked_at: string,
     *     checked_domains: list<array{domain_id: int, domain: string}>,
     *     active_ip_access_rules: list<array{domain_id: int, domain: string, rule_id: string, created_on: string|null}>,
     *     unavailable_domains: list<array{domain_id: int, domain: string}>
     * }
     */
    private function cloudflareIpAccessRuleStatus(string $ipAddress): array
    {
        $domains = MonitoredDomain::query()
            ->whereNotNull('cloudflare_zone_id')
            ->where('cloudflare_zone_id', '!=', '')
            ->where('is_owned', true)
            ->orderBy('id')
            ->get(['id', 'domain', 'cloudflare_zone_id']);

        $checkedDomains = [];
        $activeRules = [];
        $unavailableDomains = [];

        foreach ($domains as $domain) {
            $result = $this->cloudflareIpBlockService->listAccessRules((string) $domain->cloudflare_zone_id);

            if (! $result['success']) {
                $unavailableDomains[] = [
                    'domain_id' => $domain->id,
                    'domain' => $domain->domain,
                ];

                continue;
            }

            $checkedDomains[] = [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
            ];

            foreach ($result['rules'] as $rule) {
                if ($rule['ip_address'] !== $ipAddress) {
                    continue;
                }

                $activeRules[] = [
                    'domain_id' => $domain->id,
                    'domain' => $domain->domain,
                    'rule_id' => $rule['id'],
                    'created_on' => $rule['created_on'],
                ];
            }
        }

        $status = $activeRules !== []
            ? 'active'
            : ($unavailableDomains !== [] ? 'unknown' : ($checkedDomains === [] ? 'not_configured' : 'not_active'));

        return [
            'status' => $status,
            'checked_at' => now()->toIso8601String(),
            'checked_domains' => $checkedDomains,
            'active_ip_access_rules' => $activeRules,
            'unavailable_domains' => $unavailableDomains,
        ];
    }

    /**
     * Return only block locations confirmed by an authoritative source. Reported
     * telemetry outcomes are observations, not proof that a block remains active.
     *
     * @param  Collection<int, BlockedIp>  $blocks
     * @param  array{active_ip_access_rules: list<array{domain_id: int, domain: string, rule_id: string, created_on: string|null}>}  $cloudflareStatus
     * @return list<array{tier: string, source: string, scope: string, domain_id: int|null, domain: string|null, rule_id: string|null, created_on: string|null}>
     */
    private function verifiedBlockLocations(Collection $blocks, array $cloudflareStatus): array
    {
        $cloudflareLocations = collect($cloudflareStatus['active_ip_access_rules'])
            ->map(static fn (array $rule): array => [
                'tier' => 'Tier 2',
                'source' => 'Cloudflare IP Access Rule',
                'scope' => 'domain',
                'domain_id' => $rule['domain_id'],
                'domain' => $rule['domain'],
                'rule_id' => $rule['rule_id'],
                'created_on' => $rule['created_on'],
            ])
            ->all();

        $globalTier3Location = $blocks->contains('is_global', true)
            ? [[
                'tier' => 'Tier 3',
                'source' => 'Tier 3 global block list',
                'scope' => 'global',
                'domain_id' => null,
                'domain' => null,
                'rule_id' => null,
                'created_on' => null,
            ]]
            : [];

        $domainTier3Locations = $blocks
            ->where('is_global', false)
            ->map(fn (BlockedIp $block): array => [
                'tier' => 'Tier 3',
                'source' => 'Tier 3 domain block list',
                'scope' => 'domain',
                'domain_id' => $block->monitored_domain_id,
                'domain' => $block->monitoredDomain?->domain ?? 'Unknown domain',
                'rule_id' => null,
                'created_on' => null,
            ])
            ->all();

        return [...$cloudflareLocations, ...$globalTier3Location, ...$domainTier3Locations];
    }

    /**
     * @param  Collection<int, BlockedIp>  $blocks
     * @param  array{status: string}  $cloudflareStatus
     */
    private function overallBlockClassification(Collection $blocks, array $cloudflareStatus): string
    {
        if ($cloudflareStatus['status'] === 'active') {
            return 'cloudflare_ip_access_rule_active';
        }

        return match ($this->tier3BlockClassification($blocks)) {
            'global_block_list_entry' => 'tier3_global_block_list_entry',
            'domain_block_list_entry' => 'tier3_domain_block_list_entry',
            default => $cloudflareStatus['status'] === 'unknown' ? 'unknown' : 'no_known_block',
        };
    }
}
