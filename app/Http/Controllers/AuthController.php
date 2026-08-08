<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

class AuthController extends Controller
{
    public function redirect()
    {
        return Socialite::driver('google')
            ->stateless()
            ->scopes(config('services.google.scopes', []))
            ->with([
                'access_type' => 'offline',
                'prompt' => 'consent',
                'include_granted_scopes' => 'true',
            ])
            ->redirect();
    }

    public function callback()
    {
        /** @var \App\Models\User $user */
        $user = Auth::user();
        $googleUser = Socialite::driver('google')
            ->stateless()
            ->user();

        $user->update([
            'token' => null,
            'google_access_token' => $googleUser->token,
            'google_refresh_token' => $googleUser->refreshToken ?: $user->google_refresh_token,
            'google_token_expires_at' => $googleUser->expiresIn
                ? now()->addSeconds((int) $googleUser->expiresIn)
                : $user->google_token_expires_at,
        ]);

        return redirect()
            ->route('dashboard')
            ->with('success', 'Google account connected successfully.');
    }
}
