<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\ScannedEmail;
use App\Models\ScannedSms;
use Inertia\Inertia;

class DashboardController extends Controller
{
    public function index(Request $request)
    {
        /** @var \App\Models\User $user */
        $user = Auth::user();
        $isConnected = !empty($user->token);
        $filter = $request->input('filter', 'all');

        // 1. Calculate Stats
        $emailCount = $isConnected ? ScannedEmail::where('user_id', $user->id)->count() : 0;
        $smsCount = ScannedSms::where('user_id', $user->id)->count();

        $emailThreats = $isConnected ? ScannedEmail::where('user_id', $user->id)->where('is_threat', true)->count() : 0;
        $smsThreats = ScannedSms::where('user_id', $user->id)->where('is_threat', true)->count();

        $stats = [
            'emails_scanned' => $emailCount,
            'sms_scanned' => $smsCount,
            'threats' => $emailThreats + $smsThreats,
            'protected' => 1
        ];

        // 2. Build the Combined Feed
        $feed = collect([]);

        // Add Emails
        if ($isConnected) {
            $emails = ScannedEmail::where('user_id', $user->id)->latest()->take(20)->get();
            $feed = $feed->concat($emails->map(fn($e) => [
                'id' => 'email_'.$e->id,
                'source' => 'email',
                'subject' => $e->subject,
                'sender' => $e->sender,
                'is_threat' => $e->is_threat,
                'severity' => $e->severity,
                'risk_score' => $e->risk_score,
                'date_obj' => $e->created_at,
                'date' => $e->created_at->diffForHumans(),
                'snippet' => $e->snippet,
                'reason' => $e->reason ?? $e->explanation ?? 'Analysis pending...',
            ]));
        }

        // Add SMS
        $sms = ScannedSms::where('user_id', $user->id)->latest()->take(20)->get();
        $feed = $feed->concat($sms->map(fn($s) => [
            'id' => 'sms_'.$s->id,
            'source' => 'sms',
            'subject' => \Illuminate\Support\Str::limit($s->content, 40),
            'sender' => 'Text Message',
            'is_threat' => $s->is_threat,
            'severity' => $s->risk_score > 70 ? 'high' : ($s->risk_score > 40 ? 'medium' : 'low'),
            'risk_score' => $s->risk_score,
            'date_obj' => $s->created_at,
            'date' => $s->created_at->diffForHumans(),
            // 🟢 ADDED THIS LINE (Mapping explanation to reason):
            'reason' => $s->explanation ?? 'Analysis pending...',
        ]));

        // 3. Filter & Sort
        if ($filter === 'threats') {
            $feed = $feed->where('is_threat', true);
        } else if ($filter === 'email') {
            $feed = $feed->where('source', 'email');
        } else if ($filter === 'sms') {
            $feed = $feed->where('source', 'sms');
        }

        $recentAlerts = $feed->sortByDesc('date_obj')->values()->take(20);

        return Inertia::render('Dashboard', [
            'initialStats' => $stats,
            'isConnected' => $isConnected,
            'recentAlerts' => $recentAlerts,
            'filter' => $filter,
        ]);
    }

    public function disconnect()
    {
        $user = Auth::user();
        $user->update(['token' => null, 'google_id' => null]);
        return redirect()->route('dashboard')->with('success', 'Disconnected successfully.');
    }
}
