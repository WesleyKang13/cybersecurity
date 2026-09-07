<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'token' => env('POSTMARK_TOKEN'),
    ],

    'resend' => [
        'key' => env('RESEND_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],
    'google' => [
        'client_id' => env('GOOGLE_CLIENT_ID'),
        'client_secret' => env('GOOGLE_CLIENT_SECRET'),
        'redirect' => env('GOOGLE_REDIRECT_URI'),
        // These scopes allow us to read emails securely
        'scopes' => [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/gmail.readonly',
        ],
        'access_type' => 'offline', // Important: Lets us refresh the token later
        'prompt' => 'consent',      // Forces Google to give us a refresh token
    ],
    'gemini' => [
        'key' => env('GEMINI_API_KEY'),
        'mode' => env('AI_MODE', 'live'),
        'requests_per_minute' => (int) env('GEMINI_REQUESTS_PER_MINUTE', 4),
        'max_analysis_attempts' => (int) env('GEMINI_MAX_ANALYSIS_ATTEMPTS', 3),
        'lease_seconds' => (int) env('GEMINI_ANALYSIS_LEASE_SECONDS', 120),
        'retry_delays' => [60, 300, 900],
    ],
    'cloudflare' => [
        'api_token' => env('CLOUDFLARE_API_TOKEN'),
    ],
    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

];
