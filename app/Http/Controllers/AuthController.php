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
    public function callback()
    {
        try {
            // Get the user details from Google
            $googleUser = Socialite::driver('google')->user();

            // Get the tokens
            $token = $googleUser->token;
            $refreshToken = $googleUser->refreshToken;
            $expiresIn = $googleUser->expiresIn;

            // Save to our Database
            OAuthToken::updateOrCreate(
                [
                    'user_id' => Auth::id(),
                    'provider' => 'google'
                ],
                [
                    'company_id' => Auth::user()->company_id,
                    'access_token' => $token,
                    'refresh_token' => $refreshToken,
                    'expires_at' => now()->addSeconds($expiresIn),
                ]
            );

            return redirect()->route('dashboard')->with('success', 'Google Workspace Connected!');

        } catch (\Exception $e) {
            return redirect()->route('dashboard')->with('error', 'Connection failed: ' . $e->getMessage());
        }
    }
}
