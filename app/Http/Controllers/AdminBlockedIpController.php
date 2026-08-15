<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\BlockedIp;
use App\Models\SystemAuditLog;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class AdminBlockedIpController extends Controller
{
    public function index(): Response
    {
        $blockedIps = BlockedIp::query()
            ->with('monitoredDomain:id,domain')
            ->orderByDesc('created_at')
            ->get()
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

        return Inertia::render('Admin/BlockedIpsIndex', [
            'blockedIps' => $blockedIps,
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
}
