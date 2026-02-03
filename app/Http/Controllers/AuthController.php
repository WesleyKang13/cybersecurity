<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use App\Models\OAuthToken;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    // 1. Send the user to Google
    public function redirect()
    {
        return Socialite::driver('google')
            ->scopes(config('services.google.scopes'))
            ->with([
                'access_type' => 'offline',
                'prompt' => 'consent select_account'
            ])
            ->redirect();
    }

    // 2. Handle the user coming back from Google
    // 2. Handle the user coming back from Google
    public function callback()
    {
        try {
            // Get the user details from Google
            $googleUser = Socialite::driver('google')->user();

            // This fills the 'token' column we created in the migration
            $user = Auth::user();

            $user->update([
                'google_id' => $googleUser->id,
                'token' => $googleUser->token, // This saves the Access Token to your new column
                // If you added a refresh_token column to users table, save it here too:
                // 'refresh_token' => $googleUser->refreshToken,
            ]);

            return redirect()->route('dashboard')->with('success', 'Google Workspace Connected!');

        } catch (\Exception $e) {
            return redirect()->route('dashboard')->with('error', 'Connection failed: ' . $e->getMessage());
        }
    }
}
