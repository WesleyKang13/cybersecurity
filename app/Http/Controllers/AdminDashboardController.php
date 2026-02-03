<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\ScannedEmail; // <--- USE THIS, NOT Email
use Illuminate\Support\Facades\Auth;
use Inertia\Inertia;

class AdminDashboardController extends Controller
{
    public function index()
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403, 'Unauthorized action.');
        }

        // Use ScannedEmail model here
        $orgThreats = ScannedEmail::query()
            ->with('user:id,name,email')
            ->whereHas('user', function ($query) use ($user) {
                $query->where('organization_id', $user->organization_id);
            })
            ->where('severity', 'high')
            ->orderBy('created_at', 'desc')
            ->get();

        return Inertia::render('Admin/Dashboard', [
            'threats' => $orgThreats
        ]);
    }
}
