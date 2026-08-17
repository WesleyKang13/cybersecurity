<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

final class AccountSetupService
{
    public function randomUnusablePasswordHash(): string
    {
        return Hash::make(Str::random(64));
    }

    public function issue(User $user): string
    {
        $token = Password::broker()->createToken($user);

        $user->sendPasswordResetNotification($token);

        return route('password.reset', [
            'token' => $token,
            'email' => $user->email,
        ]);
    }
}
