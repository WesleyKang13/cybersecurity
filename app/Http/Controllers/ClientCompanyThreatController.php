<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\ScannedEmail;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Inertia\Inertia;
use Inertia\Response;

class ClientCompanyThreatController extends Controller
{
    public function index(Request $request): Response
    {
        $admin = $this->clientAdmin($request);
        $filters = $request->validate([
            'risk' => ['nullable', Rule::in(['all', 'critical', 'high'])],
            'review' => ['nullable', Rule::in(['all', 'reviewed', 'unreviewed'])],
        ]);
        $risk = $filters['risk'] ?? 'all';
        $review = $filters['review'] ?? 'all';
        $companyThreats = $this->companyThreatScope($admin);

        $summary = [
            'critical' => (clone $companyThreats)
                ->whereIn('severity', ['critical', 'CRITICAL'])
                ->count(),
            'high' => (clone $companyThreats)
                ->whereIn('severity', ['high', 'HIGH'])
                ->count(),
            'unreviewed' => (clone $companyThreats)
                ->whereNull('admin_reviewed_at')
                ->count(),
            'quarantined' => (clone $companyThreats)
                ->where('is_quarantined', true)
                ->count(),
        ];

        $threats = (clone $companyThreats)
            ->with([
                'user:id,company_id,name,email',
                'adminReviewedBy:id,name',
            ])
            ->when(
                $risk !== 'all',
                fn (Builder $query) => $query->whereIn('severity', [$risk, strtoupper($risk)])
            )
            ->when(
                $review === 'reviewed',
                fn (Builder $query) => $query->whereNotNull('admin_reviewed_at')
            )
            ->when(
                $review === 'unreviewed',
                fn (Builder $query) => $query->whereNull('admin_reviewed_at')
            )
            ->orderByRaw('CASE WHEN admin_reviewed_at IS NULL THEN 0 ELSE 1 END')
            ->orderByRaw("CASE LOWER(severity) WHEN 'critical' THEN 0 ELSE 1 END")
            ->latest('created_at')
            ->paginate(25)
            ->appends([
                'risk' => $risk,
                'review' => $review,
            ])
            ->through(fn (ScannedEmail $threat): array => $this->listItem($threat));

        return Inertia::render('Client/Threats/Index', [
            'threats' => $threats,
            'filters' => [
                'risk' => $risk,
                'review' => $review,
            ],
            'summary' => $summary,
        ]);
    }

    public function show(Request $request, ScannedEmail $scannedEmail): Response
    {
        $admin = $this->clientAdmin($request);
        $threat = $this->companyThreatQuery($admin)
            ->whereKey($scannedEmail->getKey())
            ->firstOrFail();

        return Inertia::render('Client/Threats/Show', [
            'threat' => $this->detailItem($threat),
        ]);
    }

    public function markReviewed(Request $request, ScannedEmail $scannedEmail): RedirectResponse
    {
        $admin = $this->clientAdmin($request);

        DB::transaction(function () use ($admin, $scannedEmail): void {
            $threat = $this->companyThreatQuery($admin)
                ->whereKey($scannedEmail->getKey())
                ->lockForUpdate()
                ->firstOrFail();

            if ($threat->admin_reviewed_at === null) {
                $threat->forceFill([
                    'admin_reviewed_at' => now(),
                    'admin_reviewed_by_user_id' => $admin->id,
                ])->save();
            }
        });

        return back()->with('success', 'Threat marked as reviewed.');
    }

    private function clientAdmin(Request $request): User
    {
        /** @var User|null $user */
        $user = $request->user();

        abort_unless($user?->hasClientAdminPortalAccess(), 403);

        return $user;
    }

    private function companyThreatQuery(User $admin): Builder
    {
        return $this->companyThreatScope($admin)
            ->with([
                'user:id,company_id,name,email',
                'adminReviewedBy:id,name',
            ]);
    }

    private function companyThreatScope(User $admin): Builder
    {
        return ScannedEmail::query()
            ->clientReviewable()
            ->forCompany((int) $admin->company_id);
    }

    /**
     * @return array<string, mixed>
     */
    private function listItem(ScannedEmail $threat): array
    {
        return [
            'id' => $threat->id,
            'employee' => [
                'name' => $threat->user->name,
                'email' => $threat->user->email,
            ],
            'sender' => $threat->sender,
            'subject' => $threat->subject,
            'scanned_at' => $threat->created_at?->toIso8601String(),
            'severity' => strtolower((string) $threat->severity),
            'risk_score' => $threat->risk_score,
            'verdict' => $threat->verdict,
            'threat_category' => $threat->threat_category,
            'is_quarantined' => $threat->is_quarantined,
            'reviewed_at' => $threat->admin_reviewed_at?->toIso8601String(),
            'reviewed_by' => $threat->adminReviewedBy?->name,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function detailItem(ScannedEmail $threat): array
    {
        return [
            ...$this->listItem($threat),
            'reasoning' => $threat->final_reasoning ?? $threat->reason,
            'origin' => $this->safeOriginMetadata($threat->origin_trace),
        ];
    }

    /**
     * @param  array<string, mixed>|null  $originTrace
     * @return array<string, mixed>|null
     */
    private function safeOriginMetadata(?array $originTrace): ?array
    {
        if ($originTrace === null) {
            return null;
        }

        $location = is_array($originTrace['location'] ?? null) ? $originTrace['location'] : [];
        $isp = is_array($originTrace['isp'] ?? null) ? $originTrace['isp'] : [];
        $authentication = is_array($originTrace['authentication'] ?? null)
            ? $originTrace['authentication']
            : [];

        return [
            'originating_ip' => $originTrace['originating_ip'] ?? null,
            'location' => [
                'country' => $location['country'] ?? null,
                'city' => $location['city'] ?? null,
            ],
            'provider_name' => $originTrace['provider_name'] ?? null,
            'organization' => $isp['organization'] ?? null,
            'origin_note' => $originTrace['origin_note'] ?? null,
            'authentication' => [
                'spf_pass' => $authentication['spf_pass'] ?? null,
                'dkim_pass' => $authentication['dkim_pass'] ?? null,
                'domain_alignment_pass' => $authentication['domain_alignment_pass'] ?? null,
            ],
            'is_hosting_provider_warning' => $originTrace['is_hosting_provider_warning'] ?? false,
            'is_proxy_or_vpn' => $originTrace['is_proxy_or_vpn'] ?? false,
        ];
    }
}
