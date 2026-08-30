<?php

return [
    'alerts' => [
        'timezone' => env('APP_TIMEZONE', config('app.timezone', 'UTC')),

        'attack_spike' => [
            'window_minutes' => (int) env('SECURITY_ATTACK_SPIKE_WINDOW_MINUTES', 10),
            'high_threshold' => (int) env('SECURITY_ATTACK_SPIKE_HIGH_THRESHOLD', 10),
            'critical_threshold' => (int) env('SECURITY_ATTACK_SPIKE_CRITICAL_THRESHOLD', 25),
        ],
    ],
];
