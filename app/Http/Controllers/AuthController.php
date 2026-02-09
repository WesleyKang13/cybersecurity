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
            $googleUser = Socialite::driver('google')->user();
            $user = Auth::user();

            // 1. Build the Full Token Array Manually
            $fullTokenData = [
                'access_token'  => $googleUser->token,
                'refresh_token' => $googleUser->refreshToken,
                'expires_in'    => $googleUser->expiresIn,
                'created'       => now()->timestamp,
            ];

            // 2. Save it to the existing 'token' column
            // Laravel will automatically turn this array into JSON text because of the cast above.
            $user->update([
                'google_id' => $googleUser->id,
                'token' => $fullTokenData,
            ]);

            return redirect()->route('dashboard')->with('success', 'Google Workspace Connected!');

        } catch (\Exception $e) {
            return redirect()->route('dashboard')->with('error', 'Connection failed: ' . $e->getMessage());
        }
    }
}
