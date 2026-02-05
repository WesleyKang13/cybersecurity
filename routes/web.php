<?php

use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\SmsController;
use App\Http\Controllers\AdminDashboardController;
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

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::post('/auth/disconnect', [DashboardController::class, 'disconnect'])->name('google.disconnect');

    Route::get('/sms-scanner', [SmsController::class, 'index'])->name('sms.index');
    Route::post('/sms-analyze', [SmsController::class, 'analyze'])->name('sms.analyze');

    Route::get('/admin/dashboard', [AdminDashboardController::class, 'index'])
            ->name('admin.dashboard');
    Route::post('/admin/users', [AdminDashboardController::class, 'storeUser'])->name('admin.users.store');
});


Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::get('/auth/redirect', [AuthController::class, 'redirect'])->name('google.connect');
    Route::get('/auth/callback', [AuthController::class, 'callback']);
});

require __DIR__.'/auth.php';
