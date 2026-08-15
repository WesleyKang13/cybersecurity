<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\MonitoredDomain;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifyAppSecretToken
{
    public function handle(Request $request, Closure $next): Response
    {
        $token = trim((string) $request->bearerToken());

        if ($token === '') {
            return $this->unauthorizedResponse('Missing bearer token.');
        }

        $domain = MonitoredDomain::query()
            ->where('app_secret_token', $token)
            ->where('is_active', true)
            ->first();

        if ($domain === null) {
            return $this->unauthorizedResponse('Invalid or inactive application secret token.');
        }

        $request->attributes->set('telemetryDomain', $domain);

        return $next($request);
    }

    private function unauthorizedResponse(string $message): JsonResponse
    {
        return response()->json([
            'message' => $message,
        ], 401);
    }
}
