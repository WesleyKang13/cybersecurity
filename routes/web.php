<?php

use App\Http\Controllers\ProfileController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\SmsController;
use App\Http\Controllers\AdminDashboardController;
use App\Http\Controllers\DomainController;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Services\GmailService;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

Route::redirect('/', '/login');

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::post('/auth/disconnect', [DashboardController::class, 'disconnect'])->name('google.disconnect');
    Route::post('/scan/mark-safe/{id}/{source}', [DashboardController::class, 'markSafe'])->name('scan.mark-safe');
    Route::delete('/scan/delete/{id}/{source}', [DashboardController::class, 'deleteRecord'])->name('scan.delete');

    Route::get('/sms-scanner', [SmsController::class, 'index'])->name('sms.index');
    Route::post('/sms-analyze', [SmsController::class, 'analyze'])->name('sms.analyze');
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/admin/dashboard', [AdminDashboardController::class, 'index'])
            ->name('admin.dashboard');
    Route::post('/admin/users', [AdminDashboardController::class, 'storeUser'])->name('admin.users.store');
    //Route::post('/admin/reports', [AdminDashboardController::class, 'generateReport'])->name('admin.reports.generate');

});

Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::get('/auth/redirect', [AuthController::class, 'redirect'])->name('google.connect');
    Route::get('/auth/callback', [AuthController::class, 'callback']);

    Route::get('/domains', [DomainController::class, 'index'])->name('domains.index');
    Route::post('/domains', [DomainController::class, 'store'])->name('domains.store');
    Route::patch('/domains/{domain}', [DomainController::class, 'update'])->name('domains.update');
    Route::delete('/domains/{domain}', [DomainController::class, 'destroy'])->name('domains.destroy');
});

require __DIR__.'/auth.php';
