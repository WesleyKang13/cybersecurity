<?php

use App\Http\Controllers\AdminBlockedIpController;
use App\Http\Controllers\AdminDashboardController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ClientCompanyThreatController;
use App\Http\Controllers\ClientDashboardController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\DnsSecurityController;
use App\Http\Controllers\DomainController;
use App\Http\Controllers\EmailScanController;
use App\Http\Controllers\Platform\ClientCompanyController;
use App\Http\Controllers\Platform\ClientCompanyUserAccountController;
use App\Http\Controllers\Platform\ClientCompanyUserController;
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

    Route::middleware('platform')->group(function () {
        Route::get('/platform/dashboard', [AdminDashboardController::class, 'index'])->name('platform.dashboard');
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

        Route::get('/domains', [DomainController::class, 'index'])->name('domains.index');
        Route::post('/domains', [DomainController::class, 'store'])->name('domains.store');
        Route::patch('/domains/{domain}', [DomainController::class, 'update'])->name('domains.update');
        Route::delete('/domains/{domain}', [DomainController::class, 'destroy'])->name('domains.destroy');

        Route::middleware('platform.owner')
            ->prefix('platform/client-companies')
            ->name('platform.client-companies.')
            ->group(function () {
                Route::get('/', [ClientCompanyController::class, 'index'])->name('index');
                Route::post('/', [ClientCompanyController::class, 'store'])->name('store');
                Route::get('/{company}', [ClientCompanyController::class, 'show'])->name('show');
                Route::patch('/{company}', [ClientCompanyController::class, 'update'])->name('update');
                Route::post('/{company}/users/accounts', [ClientCompanyUserAccountController::class, 'store'])
                    ->name('user-accounts.store');
                Route::post('/{company}/users', [ClientCompanyUserController::class, 'store'])
                    ->name('users.store');
                Route::patch('/{company}/users/{user}', [ClientCompanyUserController::class, 'update'])
                    ->name('users.update');
            });
    });

    Route::middleware('client.admin')->prefix('company')->name('company.')->group(function () {
        Route::get('/dashboard', [ClientDashboardController::class, 'index'])->name('dashboard');
        Route::get('/threats', [ClientCompanyThreatController::class, 'index'])->name('threats.index');
        Route::get('/threats/{scannedEmail}', [ClientCompanyThreatController::class, 'show'])->name('threats.show');
        Route::patch('/threats/{scannedEmail}/review', [ClientCompanyThreatController::class, 'markReviewed'])
            ->name('threats.review');
    });
});

Route::middleware(['auth', 'verified', 'platform'])->prefix('admin')->name('admin.')->group(function () {
    Route::get('/dashboard', [AdminDashboardController::class, 'index'])->name('dashboard');
    Route::get('/blocked-ips', [AdminBlockedIpController::class, 'index'])->name('blocked-ips.index');
    Route::delete('/blocked-ips/{blockedIp}', [AdminBlockedIpController::class, 'destroy'])->name('blocked-ips.destroy');
    Route::get('/threats/export', [AdminDashboardController::class, 'exportGlobalThreats'])->name('threats.export');
    Route::get('/ip-intelligence/{ip}', [AdminDashboardController::class, 'getIpIntelligence'])
        ->where('ip', '.*')
        ->name('ip-intelligence');
    Route::post('/domains/{domain}/toggle-status', [AdminDashboardController::class, 'toggleDomainStatus'])->name('domains.toggle-status');
    Route::post('/domains/{domain}/rotate-token', [AdminDashboardController::class, 'rotateAppToken'])->name('domains.rotate-token');
    Route::post('/queue/retry', [AdminDashboardController::class, 'retryAllFailedJobs'])->name('queue.retry');

    Route::middleware('platform.owner')->group(function () {
        Route::post('/users', [AdminDashboardController::class, 'storeUser'])->name('users.store');
        Route::put('/users/{user}', [AdminDashboardController::class, 'updateUser'])->name('users.update');
    });
});

Route::middleware('auth')->group(function () {
    Route::post('/api/scan-email', [EmailScanController::class, 'store'])->name('api.scan-email');
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    Route::get('/auth/redirect', [AuthController::class, 'redirect'])->name('google.connect');
    Route::get('/auth/callback', [AuthController::class, 'callback']);

    Route::post('/settings/toggle-quarantine', function (\Illuminate\Http\Request $request) {
        $user = \Illuminate\Support\Facades\Auth::user();
        $user->update(['auto_quarantine' => $request->boolean('auto_quarantine')]);

        return back()->with('success', 'Auto-Quarantine settings updated.');
    })->name('settings.quarantine.toggle');
});

require __DIR__.'/auth.php';
