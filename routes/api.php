<?php

declare(strict_types=1);

use App\Http\Controllers\Api\TelemetryController;
use App\Http\Controllers\Api\BlockedIpController;
use App\Http\Middleware\VerifyAppSecretToken;
use Illuminate\Support\Facades\Route;

Route::prefix('v1/telemetry')
    ->middleware(VerifyAppSecretToken::class)
    ->group(function (): void {
        Route::post('/threats', [TelemetryController::class, 'storeThreats']);
        Route::get('/blocked-ips', [BlockedIpController::class, 'index']);
    });
