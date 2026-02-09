<?php

namespace App\Http\Controllers;

use App\Models\ScannedEmail;
use App\Models\ScannedSms;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Inertia\Inertia;
use Carbon\Carbon;

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
           // ->whereHas('user', fn($q) => $q->where('organization_id', $user->organization_id))
            ->where('is_threat', true)
            ->orderBy('created_at', 'desc')
            ->get()
            // We keep this mapping so your frontend icons don't break
            ->map(fn($item) => [ ...$item->toArray(), 'type' => 'email' ]);

        // 2. Fetch All Users (For the User Management Sidebar)
        $orgUsers = User::where('organization_id', $user->organization_id)
            ->orderBy('created_at', 'desc')
            ->get();

        $reportData = null;

        // Check if the user passed date filters via GET request
        if ($request->filled(['start_date', 'end_date'])) {

            try {
                $start = \Carbon\Carbon::parse($request->start_date)->startOfDay();
                $end = \Carbon\Carbon::parse($request->end_date)->endOfDay();

                // Get IDs of users in this organization to filter the report data
                $orgUserIds = $orgUsers->pluck('id');

                // 1. Global Email Stats (Filtered by Org Users)
                $totalEmails = ScannedEmail::whereIn('user_id', $orgUserIds)
                    ->whereBetween('created_at', [$start, $end])->count();

                $totalEmailThreats = ScannedEmail::whereIn('user_id', $orgUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('is_threat', true)
                    ->count();

                $verifiedSafe = ScannedEmail::withTrashed() // Include soft-deleted items
                    ->whereIn('user_id', $orgUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('severity', 'verified')
                    ->count();

                // 2. Global SMS Stats (Filtered by Org Users)
                $totalSms = ScannedSms::whereIn('user_id', $orgUserIds)
                    ->whereBetween('created_at', [$start, $end])->count();

                $totalSmsThreats = ScannedSms::whereIn('user_id', $orgUserIds)
                    ->whereBetween('created_at', [$start, $end])
                    ->where('is_threat', true)
                    ->count();

                // 3. User Breakdown Loop
                $userStats = [];

                foreach ($orgUsers as $orgUser) {
                    $userEmailCount = ScannedEmail::where('user_id', $orgUser->id)
                        ->whereBetween('created_at', [$start, $end])
                        ->count();

                    // Only add user if they have activity
                    if ($userEmailCount > 0) {
                        $userThreatCount = ScannedEmail::where('user_id', $orgUser->id)
                            ->whereBetween('created_at', [$start, $end])
                            ->where('is_threat', true)
                            ->count();

                        $userVerifiedCount = ScannedEmail::withTrashed()
                            ->where('user_id', $orgUser->id)
                            ->whereBetween('created_at', [$start, $end])
                            ->where('severity', 'verified')
                            ->count();

                        $userStats[] = [
                            'name' => $orgUser->name,
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
                    'date_range' => $start->format('M d') . ' - ' . $end->format('M d, Y'),
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
                    'protection_score' => $protectionScore
                ];

            } catch (\Exception $e) {
                // If date parsing fails, reportData remains null
            }
        }

        return Inertia::render('Admin/Dashboard', [
            'threats' => $emails,
            'users' => $orgUsers,
            'reportData' => $reportData, // Now populated dynamically
            'filters' => $request->only(['start_date', 'end_date']), // Pass filters back to frontend
        ]);
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
            'organization_id' => $admin->organization_id,
            'role' => 'user',
        ]);

        return redirect()->back();
    }

//    public function generateReport(Request $request)
//     {
//         $request->validate([
//             'start_date' => 'required|date',
//             'end_date' => 'required|date|after_or_equal:start_date',
//         ]);

//         $start = Carbon::parse($request->start_date)->startOfDay();
//         $end = Carbon::parse($request->end_date)->endOfDay();

//         // --- 1. Global Email Stats ---
//         $totalEmails = ScannedEmail::whereBetween('created_at', [$start, $end])->count();

//         $totalEmailThreats = ScannedEmail::whereBetween('created_at', [$start, $end])
//             ->where('is_threat', true)
//             ->count();

//         // 👇 NEW: Explicitly count "Verified Safe" items
//         $verifiedSafe = ScannedEmail::withTrashed() // Include deleted if you soft-delete them
//             ->whereBetween('created_at', [$start, $end])
//             ->where('severity', 'verified') // The specific flag you requested
//             ->count();

//         // --- 2. Global SMS Stats ---
//         $totalSms = ScannedSms::whereBetween('created_at', [$start, $end])->count();
//         $totalSmsThreats = ScannedSms::whereBetween('created_at', [$start, $end])
//             ->where('is_threat', true)
//             ->count();

//         // --- 3. User Breakdown Loop ---
//         $allUsers = User::all();
//         $userStats = [];

//         foreach ($allUsers as $user) {
//             $userEmailCount = ScannedEmail::where('user_id', $user->id)
//                 ->whereBetween('created_at', [$start, $end])
//                 ->count();

//             $userThreatCount = ScannedEmail::where('user_id', $user->id)
//                 ->whereBetween('created_at', [$start, $end])
//                 ->where('is_threat', true)
//                 ->count();

//             // 👇 NEW: Count Verified Safe for this specific user
//             $userVerifiedCount = ScannedEmail::withTrashed()
//                 ->where('user_id', $user->id)
//                 ->whereBetween('created_at', [$start, $end])
//                 ->where('severity', 'verified')
//                 ->count();

//             if ($userEmailCount > 0) {
//                 $userStats[] = [
//                     'name' => $user->name,
//                     'email_count' => $userEmailCount,
//                     'threat_count' => $userThreatCount,
//                     'verified_count' => $userVerifiedCount, // Pass this to frontend
//                 ];
//             }
//         }

//         // --- 4. Protection Score ---
//         $totalItems = $totalEmails + $totalSms;
//         $totalThreats = $totalEmailThreats + $totalSmsThreats;

//         $protectionScore = 100;
//         if ($totalItems > 0) {
//             $protectionScore = round((($totalItems - $totalThreats) / $totalItems) * 100, 1);
//         }

//         return Inertia::render('Admin/Dashboard', [
//             'threats' => ScannedEmail::where('is_threat', true)->limit(5)->get(),
//             'users' => User::all(),
//             'reportData' => [
//                 'date_range' => $start->format('M d') . ' - ' . $end->format('M d, Y'),
//                 'email_stats' => [
//                     'total' => $totalEmails,
//                     'threats' => $totalEmailThreats,
//                     'verified_safe' => $verifiedSafe, // Updated variable
//                 ],
//                 'sms_stats' => [
//                     'total' => $totalSms,
//                     'threats' => $totalSmsThreats,
//                 ],
//                 'user_breakdown' => $userStats,
//                 'protection_score' => $protectionScore
//             ]
//         ]);
//     }
}
