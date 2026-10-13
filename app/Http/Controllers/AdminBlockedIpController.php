<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\BlockedIp;
use App\Models\SecurityThreatLog;
use App\Models\SystemAuditLog;
use App\Support\ThreatEventPresentation;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class AdminBlockedIpController extends Controller
{
    public function index(): Response
    {
        $blockedIpModels = BlockedIp::query()
            ->with('monitoredDomain:id,domain')
            ->orderByDesc('created_at')
            ->get();

        $blockedIps = $blockedIpModels
            ->map(static function (BlockedIp $blockedIp): array {
                return [
                    'id' => $blockedIp->id,
                    'ip' => $blockedIp->ip,
                    'is_global' => (bool) $blockedIp->is_global,
                    'reason' => $blockedIp->reason,
                    'target_domain' => $blockedIp->monitoredDomain?->domain,
                    'blocked_at' => $blockedIp->created_at?->toIso8601String(),
                ];
            })
            ->values()
            ->all();

        $eventsByIp = SecurityThreatLog::query()
            ->with('monitoredDomain:id,domain')
            ->whereIn('attacker_ip', $blockedIpModels->pluck('ip')->unique())
            ->orderByDesc('detected_at')
            ->get()
            ->groupBy('attacker_ip');

        $blockedIpActivity = $blockedIpModels
            ->map(function (BlockedIp $blockedIp) use ($eventsByIp): array {
                $events = collect($eventsByIp->get($blockedIp->ip, collect()))
                    ->filter(function (SecurityThreatLog $event) use ($blockedIp): bool {
                        $occurredAfterBlock = $event->detected_at !== null
                            && $blockedIp->created_at !== null
                            && $event->detected_at->greaterThanOrEqualTo($blockedIp->created_at);
                        $matchesScope = $blockedIp->is_global
                            || $event->monitored_domain_id === $blockedIp->monitored_domain_id;

                        return $occurredAfterBlock && $matchesScope;
                    })
                    ->values();
                $latestEvent = $events->first();

                return [
                    'blocked_ip_id' => $blockedIp->id,
                    'ip' => $blockedIp->ip,
                    'is_global' => (bool) $blockedIp->is_global,
                    'target_domain' => $blockedIp->monitoredDomain?->domain,
                    'blocked_at' => $blockedIp->created_at?->toIso8601String(),
                    'attempt_count' => $events->count(),
                    'latest_attempt' => $latestEvent !== null ? $this->activityEvent($latestEvent) : null,
                    'history' => $events
                        ->take(5)
                        ->map(fn (SecurityThreatLog $event): array => $this->activityEvent($event))
                        ->all(),
                ];
            })
            ->filter(static fn (array $activity): bool => $activity['attempt_count'] > 0)
            ->values()
            ->all();

        return Inertia::render('Admin/BlockedIpsIndex', [
            'blockedIps' => $blockedIps,
            'blockedIpActivity' => $blockedIpActivity,
        ]);
    }

    public function destroy(Request $request, BlockedIp $blockedIp): RedirectResponse
    {
        $blockedIp->loadMissing('monitoredDomain:id,domain');

        $auditTargetId = (string) $blockedIp->id;
        $ipAddress = $blockedIp->ip;
        $targetDomain = $blockedIp->monitoredDomain?->domain;
        $scope = $blockedIp->is_global ? 'global' : 'domain';

        $blockedIp->delete();

        SystemAuditLog::create([
            'user_id' => $request->user()?->id,
            'action' => 'unblocked_ip',
            'target_type' => 'blocked_ip',
            'target_id' => $auditTargetId,
            'metadata' => [
                'ip' => $ipAddress,
                'scope' => $scope,
                'domain' => $targetDomain,
            ],
        ]);

        return redirect()
            ->route('admin.blocked-ips.index')
            ->with(
                'success',
                $targetDomain
                    ? "IP {$ipAddress} unblocked for {$targetDomain}."
                    : "IP {$ipAddress} unblocked successfully."
            );
    }

    /**
     * @return array{id: int, detected_at: string|null, domain: string, path_targeted: string|null, event_type: string|null, action_label: string, source_label: string}
     */
    private function activityEvent(SecurityThreatLog $event): array
    {
        return [
            'id' => $event->id,
            'detected_at' => $event->detected_at?->toIso8601String(),
            'domain' => $event->monitoredDomain?->domain ?? 'Unknown domain',
            'path_targeted' => $event->path_targeted,
            'event_type' => $event->event_type,
            'action_label' => ThreatEventPresentation::actionLabel($event->action_taken),
            'source_label' => ThreatEventPresentation::sourceLabel($event->threat_source),
        ];
    }
}
