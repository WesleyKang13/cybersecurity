<?php

namespace App\Http\Controllers;

use App\Models\MonitoredDomain;
use App\Models\ScannedEmail;
use App\Models\ScannedSms;
use App\Models\SecurityThreatLog;
use App\Models\SystemAuditLog;
use App\Models\User;
use App\Models\WhitelistedDomain;
use App\Services\IpIntelligenceService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Inertia\Inertia;
use Throwable;

class AdminDashboardController extends Controller
{
    public function index(Request $request)
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        // --- EXISTING CODE (KEPT AS IS) ---

        // 1. Fetch High Threat Emails ONLY (Sorted by newest first)
        $emails = ScannedEmail::with('user:id,name')
            ->where('is_threat', true)
            ->orderBy('created_at', 'desc')
            ->get()
            // We keep this mapping so your frontend icons don't break
            ->map(fn ($item) => [...$item->toArray(), 'type' => 'email']);

        // 2. Fetch All Users (For the User Management Sidebar)
        $companyUsers = User::where('company_id', $user->company_id)
            ->orderBy('created_at', 'desc')
            ->get();

        $reportData = null;

        // Check if the user passed date filters via GET request
        if ($request->filled(['start_date', 'end_date'])) {

            try {
                $start = \Carbon\Carbon::parse($request->start_date)->startOfDay();
                $end = \Carbon\Carbon::parse($request->end_date)->endOfDay();

                // Get IDs of users in this company to filter the report data
                $companyUserIds = $companyUsers->pluck('id');

                // 1. Global Email Stats (Filtered by Company Users)
                $totalEmails = ScannedEmail::whereIn('user_id', $companyUserIds)
                    ->whereBetween('created_at', [$start, $end])->count();

                $totalEmailThreats = ScannedEmail::whereIn('user_id', $companyUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('is_threat', true)
                    ->count();

                $verifiedSafe = ScannedEmail::withTrashed() // Include soft-deleted items
                    ->whereIn('user_id', $companyUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('severity', 'verified')
                    ->count();

                // 2. Global SMS Stats (Filtered by Company Users)
                $totalSms = ScannedSms::whereIn('user_id', $companyUserIds)
                    ->whereBetween('created_at', [$start, $end])->count();

                $totalSmsThreats = ScannedSms::whereIn('user_id', $companyUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('is_threat', true)
                    ->count();

                // 3. User Breakdown Loop
                $userStats = [];

                foreach ($companyUsers as $companyUser) {
                    $userEmailCount = ScannedEmail::where('user_id', $companyUser->id)
                        ->whereBetween('created_at', [$start, $end])
                        ->count();

                    // Only add user if they have activity
                    if ($userEmailCount > 0) {
                        $userThreatCount = ScannedEmail::where('user_id', $companyUser->id)
                            ->whereBetween('created_at', [$start, $end])
                            ->where('is_threat', true)
                            ->count();

                        $userVerifiedCount = ScannedEmail::withTrashed()
                            ->where('user_id', $companyUser->id)
                            ->whereBetween('created_at', [$start, $end])
                            ->where('severity', 'verified')
                            ->count();

                        $userStats[] = [
                            'name' => $companyUser->name,
                            'email_count' => $userEmailCount,
                            'threat_count' => $userThreatCount,
                            'verified_count' => $userVerifiedCount,
                        ];
                    }
                }

                // 4. Protection Score Calculation
                $totalItems = $totalEmails + $totalSms;
                $totalThreats = $totalEmailThreats + $totalSmsThreats;

                $protectionScore = 100;
                if ($totalItems > 0) {
                    $protectionScore = round((($totalItems - $totalThreats) / $totalItems) * 100, 1);
                }

                $reportData = [
                    'date_range' => $start->format('M d').' - '.$end->format('M d, Y'),
                    'email_stats' => [
                        'total' => $totalEmails,
                        'threats' => $totalEmailThreats,
                        'verified_safe' => $verifiedSafe,
                    ],
                    'sms_stats' => [
                        'total' => $totalSms,
                        'threats' => $totalSmsThreats,
                    ],
                    'user_breakdown' => $userStats,
                    'protection_score' => $protectionScore,
                ];

            } catch (\Exception $e) {
                // If date parsing fails, reportData remains null
            }
        }

        $domains = WhitelistedDomain::orderBy('created_at', 'desc')->get();
        $jobsTable = (string) config('queue.connections.database.table', 'jobs');
        $failedJobsTable = (string) config('queue.failed.table', 'failed_jobs');
        $pendingJobsCount = Schema::hasTable($jobsTable)
            ? (int) DB::table($jobsTable)->count()
            : 0;
        $failedJobsCount = Schema::hasTable($failedJobsTable)
            ? (int) DB::table($failedJobsTable)->count()
            : 0;
        $recentFailedJobs = Schema::hasTable($failedJobsTable)
            ? DB::table($failedJobsTable)
                ->select(['id', 'queue', 'payload', 'exception', 'failed_at'])
                ->orderByDesc('failed_at')
                ->limit(5)
                ->get()
                ->map(function ($job): array {
                    return [
                        'id' => $job->id,
                        'queue' => $job->queue,
                        'payload' => $job->payload,
                        'exception' => $job->exception,
                        'failed_at' => $job->failed_at,
                    ];
                })
                ->values()
                ->all()
            : [];
        $topTargetedPaths = SecurityThreatLog::query()
            ->selectRaw('path_targeted, COUNT(*) as event_count')
            ->whereNotNull('path_targeted')
            ->where('path_targeted', '!=', '')
            ->groupBy('path_targeted')
            ->orderByDesc('event_count')
            ->limit(5)
            ->get()
            ->map(function (SecurityThreatLog $log): array {
                return [
                    'path_targeted' => $log->path_targeted,
                    'count' => (int) $log->event_count,
                ];
            })
            ->values()
            ->all();
        $topAttackerIps = SecurityThreatLog::query()
            ->selectRaw('attacker_ip, COUNT(*) as event_count')
            ->whereNotNull('attacker_ip')
            ->where('attacker_ip', '!=', '')
            ->groupBy('attacker_ip')
            ->orderByDesc('event_count')
            ->limit(10)
            ->get()
            ->map(function (SecurityThreatLog $log): array {
                return [
                    'attacker_ip' => $log->attacker_ip,
                    'count' => (int) $log->event_count,
                ];
            })
            ->values()
            ->all();
        $tier3Domains = MonitoredDomain::query()
            ->where('infrastructure_type', 'app_middleware')
            ->withCount('securityThreatLogs')
            ->orderBy('domain')
            ->get()
            ->makeVisible('app_secret_token');
        $auditLogs = SystemAuditLog::query()
            ->with('user:id,name,email')
            ->latest()
            ->limit(50)
            ->get()
            ->map(function (SystemAuditLog $log): array {
                return [
                    'id' => $log->id,
                    'action' => $log->action,
                    'target_type' => $log->target_type,
                    'target_id' => $log->target_id,
                    'metadata' => $log->metadata,
                    'created_at' => $log->created_at?->toIso8601String(),
                    'updated_at' => $log->updated_at?->toIso8601String(),
                    'user' => $log->user ? [
                        'id' => $log->user->id,
                        'name' => $log->user->name,
                        'email' => $log->user->email,
                    ] : null,
                ];
            })
            ->values()
            ->all();

        return Inertia::render('Admin/Dashboard', [
            'threats' => $emails,
            'users' => $companyUsers,
            'reportData' => $reportData,
            'filters' => $request->only(['start_date', 'end_date']),
            'domains' => $domains,
            'pending_jobs_count' => $pendingJobsCount,
            'failed_jobs_count' => $failedJobsCount,
            'recent_failed_jobs' => $recentFailedJobs,
            'top_targeted_paths' => $topTargetedPaths,
            'top_attacker_ips' => $topAttackerIps,
            'tier_3_domains' => $tier3Domains,
            'audit_logs' => $auditLogs,
        ]);
    }

    public function exportGlobalThreats(Request $request): JsonResponse
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        $logs = SecurityThreatLog::query()
            ->with('monitoredDomain:id,domain')
            ->orderByDesc('detected_at')
            ->limit(10000)
            ->get();

        return response()->json(
            $logs,
            200,
            ['Content-Disposition' => 'attachment; filename=global_threat_feed.json']
        );
    }

    public function getIpIntelligence(string $ip, IpIntelligenceService $ipIntelligenceService): JsonResponse
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return response()->json([
                'success' => false,
                'message' => 'Enter a valid IP address.',
            ], 422);
        }

        try {
            $result = $ipIntelligenceService->lookup($ip);

            if (($result['status'] ?? 'fail') !== 'success') {
                return response()->json([
                    'success' => false,
                    'message' => $result['message'] ?? 'IP intelligence lookup failed.',
                    'data' => $result,
                ], 502);
            }

            return response()->json([
                'success' => true,
                'data' => $result,
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'success' => false,
                'message' => 'Unable to load IP intelligence at this time.',
            ], 500);
        }
    }

    public function rotateAppToken(MonitoredDomain $domain): RedirectResponse
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        if ($domain->infrastructure_type !== 'app_middleware') {
            return back()->with('error', 'Token rotation is only available for Tier 3 middleware domains.');
        }

        $domain->update([
            'app_secret_token' => Str::random(64),
        ]);

        SystemAuditLog::create([
            'user_id' => $user->id,
            'action' => 'rotated_tier_3_token',
            'target_type' => 'domain',
            'target_id' => (string) $domain->id,
            'metadata' => [
                'domain' => $domain->domain,
                'infrastructure_type' => $domain->infrastructure_type,
            ],
        ]);

        return back()->with('success', "Tier 3 token rotated for {$domain->domain}.");
    }

    public function toggleDomainStatus(MonitoredDomain $domain): RedirectResponse
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        if ($domain->infrastructure_type !== 'app_middleware') {
            return back()->with('error', 'Status toggling is only available for Tier 3 middleware domains.');
        }

        $domain->is_active = ! $domain->is_active;
        $domain->save();

        SystemAuditLog::create([
            'user_id' => $user->id,
            'action' => $domain->is_active ? 'enabled_tier_3_token' : 'disabled_tier_3_token',
            'target_type' => 'domain',
            'target_id' => (string) $domain->id,
            'metadata' => [
                'domain' => $domain->domain,
                'is_active' => $domain->is_active,
                'infrastructure_type' => $domain->infrastructure_type,
            ],
        ]);

        return back()->with('success', 'Domain status updated successfully.');
    }

    public function retryAllFailedJobs(Request $request): RedirectResponse
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        $failedJobsTable = (string) config('queue.failed.table', 'failed_jobs');

        if (! Schema::hasTable($failedJobsTable)) {
            return back()->with('error', 'Failed jobs storage is not available in this environment.');
        }

        try {
            Artisan::call('queue:retry', ['id' => 'all']);
        } catch (Throwable $e) {
            return back()->with('error', 'Unable to retry failed jobs: '.$e->getMessage());
        }

        SystemAuditLog::create([
            'user_id' => $user->id,
            'action' => 'retried_failed_jobs',
            'metadata' => [
                'command' => 'queue:retry all',
            ],
        ]);

        return back()->with('success', 'All failed jobs have been queued for retry.');
    }

    // Function to Add a User (Kept exactly as is)
    public function storeUser(Request $request)
    {
        $admin = Auth::user();

        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
        ]);

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make('password'),
            'company_id' => $admin->company_id,
            'role' => 'user',
        ]);

        return redirect()->back();
    }

    // Function to Edit/Update a User
    public function updateUser(Request $request, User $user)
    {
        $admin = Auth::user();

        // 1. Security Check: Only admins can edit, and only users in their company
        if ($admin->role !== 'admin' || $user->company_id !== $admin->company_id) {
            abort(403, 'Unauthorized action.');
        }

        // 2. Validate input
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            // Ensure unique email, but ignore the current user's email
            'email' => ['required', 'string', 'email', 'max:255', \Illuminate\Validation\Rule::unique('users')->ignore($user->id)],
            'role' => 'required|string|in:user,admin',
            'password' => 'nullable|string|min:8',
        ]);

        // 3. Handle optional password update
        if ($request->filled('password')) {
            $validated['password'] = Hash::make($validated['password']);
        } else {
            unset($validated['password']);
        }

        // 4. Update the user
        $user->update($validated);

        return redirect()->back();
    }
}
