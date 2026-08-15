<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\MonitoredDomain;
use App\Services\AppThreatService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class TelemetryController extends Controller
{
    public function storeThreats(Request $request, AppThreatService $appThreatService): JsonResponse
    {
        $domain = $this->telemetryDomain($request);
        $events = $this->validatedThreatEvents($request);
        $result = $appThreatService->ingestThreatEvents($domain, $events);

        return response()->json([
            'success' => true,
            'domain' => $domain->domain,
            'events_received' => count($events),
            'events_synced' => $result['events_synced'],
            'new_events_count' => $result['new_events_count'],
        ], 202);
    }

    /**
     * @return list<array{
     *     attacker_ip: string,
     *     targeted_path: string,
     *     user_agent: string,
     *     timestamp: string
     * }>
     */
    private function validatedThreatEvents(Request $request): array
    {
        $payload = $request->json()->all();
        $events = array_is_list($payload)
            ? $payload
            : ($payload['threats'] ?? $payload['events'] ?? []);

        $validator = Validator::make(
            ['threats' => $events],
            [
                'threats' => ['required', 'array', 'min:1'],
                'threats.*.attacker_ip' => ['required', 'ip'],
                'threats.*.targeted_path' => ['required', 'string', 'max:2048'],
                'threats.*.user_agent' => ['required', 'string', 'max:10000'],
                'threats.*.timestamp' => ['required', 'date'],
            ]
        );

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        /** @var list<array{attacker_ip: string, targeted_path: string, user_agent: string, timestamp: string}> $validated */
        $validated = $validator->validated()['threats'];

        return $validated;
    }

    private function telemetryDomain(Request $request): MonitoredDomain
    {
        /** @var MonitoredDomain|null $domain */
        $domain = $request->attributes->get('telemetryDomain');

        abort_if($domain === null, 401, 'Unauthorized.');

        return $domain;
    }
}
