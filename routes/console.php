<?php

use Illuminate\Support\Facades\Schedule;
use App\Models\User;
use App\Jobs\ScanGmailJob;

// This runs every minute automatically
Schedule::call(function () {
    // Loop through all users and dispatch the scanner job for them
    $users = User::whereNotNull('email')->get();

    foreach ($users as $user) {
        // Only scan if they have a token (we check this inside the job too, but good optimization)
        if ($user->token) {
            ScanGmailJob::dispatch($user);
        }
    }
})->everyMinute();
