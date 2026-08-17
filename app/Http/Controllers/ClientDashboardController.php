<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\ScannedEmail;
use App\Models\User;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class ClientDashboardController extends Controller
{
    public function index(Request $request): Response
    {
        /** @var User $admin */
        $admin = $request->user();
        $companyThreats = ScannedEmail::query()
            ->clientReviewable()
            ->forCompany((int) $admin->company_id);

        return Inertia::render('Client/Dashboard', [
            'threatSummary' => [
                'high_critical' => (clone $companyThreats)->count(),
                'critical' => (clone $companyThreats)
                    ->whereIn('severity', ['critical', 'CRITICAL'])
                    ->count(),
                'high' => (clone $companyThreats)
                    ->whereIn('severity', ['high', 'HIGH'])
                    ->count(),
                'unreviewed' => (clone $companyThreats)->whereNull('admin_reviewed_at')->count(),
                'quarantined' => (clone $companyThreats)->where('is_quarantined', true)->count(),
                'recent' => (clone $companyThreats)->where('created_at', '>=', now()->subDays(7))->count(),
            ],
        ]);
    }
}
