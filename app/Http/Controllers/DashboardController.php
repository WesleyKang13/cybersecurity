<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\ScannedEmail;
use Inertia\Inertia;

class DashboardController extends Controller
{
    public function index(Request $request)
    {
        /** @var \App\Models\User $user */
        $user = Auth::user();
        $isConnected = !empty($user->token);

        // Get the filter from the URL (?filter=threats)
        $filter = $request->input('filter', 'all');

        $stats = [
            'scanned' => 0,
            'threats' => 0,
            'protected' => 0
        ];

        $recentAlerts = [];

        if ($isConnected) {
            // 1. Always calculate total stats (regardless of filter)
            $stats['scanned'] = ScannedEmail::where('user_id', $user->id)->count();
            $stats['threats'] = ScannedEmail::where('user_id', $user->id)->where('is_threat', true)->count();
            $stats['protected'] = 1;

            // 2. Query for the list (Respecting the filter)
            $query = ScannedEmail::where('user_id', $user->id);

            if ($filter === 'threats') {
                $query->where('is_threat', true);
            }

            $recentAlerts = $query->latest()
                ->take(20)
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
                        'is_threat' => $email->is_threat,
                        'date' => $email->created_at->diffForHumans(),
                    ];
                });
        }

        return Inertia::render('Dashboard', [
            'initialStats' => $stats,
            'isConnected' => $isConnected,
            'recentAlerts' => $recentAlerts,
            'filter' => $filter, // Pass the active filter to UI
        ]);
    }

    // New: Handle Disconnect
    public function disconnect()
    {
        $user = Auth::user();
        $user->update([
            'token' => null,
            'google_id' => null,
            // 'refresh_token' => null // uncomment if you use this
        ]);

        return redirect()->route('dashboard')->with('success', 'Disconnected successfully.');
    }
}
