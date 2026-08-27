<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\BlockedIp;
use App\Models\SecurityThreatLog;
use Carbon\Carbon;
use Illuminate\Support\Collection;

class AttackerIntelligenceService
{
    public function __construct(private readonly IpIntelligenceService $ipIntelligenceService) {}

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
                    'blocked_status' => $this->blockClassification($blocks),
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

        return [
            'classification' => $this->blockClassification($blocks),
            'globally_blocked' => $blocks->contains('is_global', true),
            'domain_specific_blocks' => $blocks
                ->where('is_global', false)
                ->map(fn (BlockedIp $block): array => [
                    'domain_id' => $block->monitored_domain_id,
                    'domain' => $block->monitoredDomain?->domain ?? 'Unknown domain',
                ])
                ->values()
                ->all(),
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
    private function blockClassification(Collection $blocks): string
    {
        if ($blocks->contains('is_global', true)) {
            return 'global';
        }

        if ($blocks->contains('is_global', false)) {
            return 'domain_specific';
        }

        return 'not_blocked';
    }
}
