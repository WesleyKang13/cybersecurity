<?php

namespace App\Http\Controllers;

use App\Models\ScannedEmail;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Inertia\Inertia;

class AdminDashboardController extends Controller
{
    public function index()
    {
        $user = Auth::user();

        if ($user->role !== 'admin') {
            abort(403);
        }

        // 1. Fetch High Threat Emails ONLY (Sorted by newest first)
        $emails = ScannedEmail::with('user:id,name')
            ->whereHas('user', fn($q) => $q->where('organization_id', $user->organization_id))
            ->where('severity', 'high')
            ->orderBy('created_at', 'desc')
            ->get()
            // We keep this mapping so your frontend icons don't break
            ->map(fn($item) => [ ...$item->toArray(), 'type' => 'email' ]);

        // 2. Fetch All Users (For the User Management Sidebar)
        $orgUsers = User::where('organization_id', $user->organization_id)
            ->orderBy('created_at', 'desc')
            ->get();

        return Inertia::render('Admin/Dashboard', [
            'threats' => $emails, // Now contains only emails
            'users' => $orgUsers,
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
}
