<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\BlockedIp;
use App\Models\MonitoredDomain;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class BlockedIpController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $domain = $this->telemetryDomain($request);

        $blockedIps = BlockedIp::query()
            ->where(function ($query) use ($domain): void {
                $query
                    ->where('is_global', true)
                    ->orWhere('monitored_domain_id', $domain->id);
            })
            ->orderBy('ip')
            ->pluck('ip')
            ->filter(static fn (mixed $ip): bool => is_string($ip) && trim($ip) !== '')
            ->unique()
            ->values()
            ->all();

        return response()->json($blockedIps);
    }

    private function telemetryDomain(Request $request): MonitoredDomain
    {
        /** @var MonitoredDomain|null $domain */
        $domain = $request->attributes->get('telemetryDomain');

        abort_if($domain === null, 401, 'Unauthorized.');

        return $domain;
    }
}
