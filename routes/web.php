<?php

use App\Http\Controllers\AdminDashboardController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\DnsSecurityController;
use App\Http\Controllers\DomainController;
use App\Http\Controllers\EmailScanController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\SmsController;
use Illuminate\Support\Facades\Route;

Route::redirect('/', '/login');

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::post('/auth/disconnect', [DashboardController::class, 'disconnect'])->name('google.disconnect');
    Route::post('/scan/mark-safe/{id}/{source}', [DashboardController::class, 'markSafe'])->name('scan.mark-safe');
    Route::delete('/scan/delete/{id}/{source}', [DashboardController::class, 'deleteRecord'])->name('scan.delete');

    Route::get('/sms-scanner', [SmsController::class, 'index'])->name('sms.index');
    Route::post('/sms-analyze', [SmsController::class, 'analyze'])->name('sms.analyze');
    Route::get('/dns-security', [DnsSecurityController::class, 'index'])->name('dns-security.index');
    Route::post('/dns-security', [DnsSecurityController::class, 'store'])->name('dns-security.store');
    Route::post('/dns-security/alert-settings', [DnsSecurityController::class, 'updateAlertSettings'])->name('dns-security.alert-settings');
    Route::post('/dns-security/block-ip', [DnsSecurityController::class, 'blockIp'])->name('dns-security.block-ip');
    Route::post('/dns-security/unblock-ip', [DnsSecurityController::class, 'unblockIp'])->name('dns-security.unblock-ip');
    Route::patch('/dns-security/{domain}', [DnsSecurityController::class, 'update'])->name('dns-security.update');
    Route::get('/dns-security/ip-lookup/{ip}', [DnsSecurityController::class, 'lookupIp'])
        ->where('ip', '.*')
        ->name('dns-security.ip-lookup');
    Route::post('/dns-security/{domain}/scan', [DnsSecurityController::class, 'scan'])->name('dns-security.scan');
    Route::delete('/dns-security/{domain}', [DnsSecurityController::class, 'destroy'])->name('dns-security.destroy');

    Route::get('/admin/dashboard', [AdminDashboardController::class, 'index'])
            ->name('admin.dashboard');
    Route::post('/admin/users', [AdminDashboardController::class, 'storeUser'])->name('admin.users.store');
    Route::put('/admin/users/{user}', [AdminDashboardController::class, 'updateUser'])->name('admin.users.update');
});

Route::middleware('auth')->group(function () {
    Route::post('/api/scan-email', [EmailScanController::class, 'store'])->name('api.scan-email');
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::get('/auth/redirect', [AuthController::class, 'redirect'])->name('google.connect');
    Route::get('/auth/callback', [AuthController::class, 'callback']);

    Route::get('/domains', [DomainController::class, 'index'])->name('domains.index');
    Route::post('/domains', [DomainController::class, 'store'])->name('domains.store');
    Route::patch('/domains/{domain}', [DomainController::class, 'update'])->name('domains.update');
    Route::delete('/domains/{domain}', [DomainController::class, 'destroy'])->name('domains.destroy');

    Route::post('/settings/toggle-quarantine', function (\Illuminate\Http\Request $request) {
        $user = \Illuminate\Support\Facades\Auth::user();
        $user->update(['auto_quarantine' => $request->boolean('auto_quarantine')]);
        return back()->with('success', 'Auto-Quarantine settings updated.');
    })->name('settings.quarantine.toggle');
});

require __DIR__.'/auth.php';
