<?php

use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AuthController;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Services\GmailService;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

Route::get('/', function () {
    return Inertia::render('Welcome', [
        'canLogin' => Route::has('login'),
        'canRegister' => Route::has('register'),
        'laravelVersion' => Application::VERSION,
        'phpVersion' => PHP_VERSION,
    ]);
});

Route::get('/dashboard', function () {
    /** @var \App\Models\User $user */
    $user = Auth::user();

    // 1. Check connection
    $isConnected = $user->relationLoaded('token') ? !is_null($user->token) : $user->token()->exists();

    $stats = [
        'scanned' => 0,
        'threats' => 0,
        'protected' => 0
    ];

    // 2. Fetch real stats if connected
    if ($isConnected) {
        try {
            // Count "Scanned" from our local DB (or Google if you prefer)
            $stats['scanned'] = ScannedEmail::where('user_id', $user->id)->count();
            $stats['threats'] = ScannedEmail::where('user_id', $user->id)->where('is_threat', true)->count();
            $stats['protected'] = 1;
        } catch (\Exception $e) {
            // connection error logic
        }
    }

    // 3. Fetch the Recent Alerts (Last 5 emails)
    $recentAlerts = ScannedEmail::where('user_id', $user->id)
        ->latest()
        ->take(10) // Let's show 10 now
        ->get()
        ->map(function ($email) {
            return [
                'id' => $email->id,
                'severity' => $email->severity,
                'subject' => $email->subject,
                'sender' => $email->sender,
                'snippet' => $email->snippet,
                'risk_score' => $email->risk_score,
                'reason' => $email->reason,
                'recipient' => 'You',
                'date' => $email->created_at->diffForHumans(),
            ];
        });

    return Inertia::render('Dashboard', [
        'initialStats' => $stats,
        'isConnected' => $isConnected,
        'recentAlerts' => $recentAlerts, // 👈 Passing the list to React
    ]);
})->middleware(['auth', 'verified'])->name('dashboard');

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::get('/auth/redirect', [AuthController::class, 'redirect'])->name('google.connect');
    Route::get('/auth/callback', [AuthController::class, 'callback']);
});

require __DIR__.'/auth.php';
