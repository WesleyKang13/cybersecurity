<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\MonitoredDomain;
use App\Rules\SafeThreatMetadata;
use App\Services\AppThreatService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class TelemetryController extends Controller
{
    private const MAX_PAYLOAD_BYTES = 524288;

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
     *     timestamp: string,
     *     event_type?: string|null,
     *     severity?: string|null,
     *     reason?: string|null,
     *     metadata?: array<array-key, mixed>|null
     * }>
     */
    private function validatedThreatEvents(Request $request): array
    {
        if (strlen($request->getContent()) > self::MAX_PAYLOAD_BYTES) {
            throw ValidationException::withMessages([
                'payload' => 'The telemetry payload must not exceed 512 KB.',
            ]);
        }

        $payload = $request->json()->all();
        $events = array_is_list($payload)
            ? $payload
            : ($payload['threats'] ?? $payload['events'] ?? []);

        $validator = Validator::make(
            ['threats' => $events],
            [
                'threats' => ['required', 'array', 'min:1', 'max:100'],
                'threats.*.attacker_ip' => ['required', 'ip'],
                'threats.*.targeted_path' => ['required', 'string', 'max:2048'],
                'threats.*.user_agent' => ['required', 'string', 'max:10000'],
                'threats.*.timestamp' => ['required', 'date'],
                'threats.*.event_type' => [
                    'sometimes',
                    'nullable',
                    'string',
                    'max:100',
                    'regex:/^[a-z0-9]+(?:_[a-z0-9]+)*$/',
                ],
                'threats.*.severity' => [
                    'sometimes',
                    'nullable',
                    'string',
                    Rule::in(['info', 'low', 'medium', 'high', 'critical']),
                ],
                'threats.*.reason' => ['sometimes', 'nullable', 'string', 'max:2000'],
                'threats.*.metadata' => ['sometimes', 'nullable', 'array', new SafeThreatMetadata],
            ]
        );

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        /** @var list<array{attacker_ip: string, targeted_path: string, user_agent: string, timestamp: string, event_type?: string|null, severity?: string|null, reason?: string|null, metadata?: array<array-key, mixed>|null}> $validated */
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
