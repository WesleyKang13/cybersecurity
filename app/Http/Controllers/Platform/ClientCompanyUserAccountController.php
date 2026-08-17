<?php

declare(strict_types=1);

namespace App\Http\Controllers\Platform;

use App\Http\Controllers\Controller;
use App\Models\Company;
use App\Models\User;
use App\Services\AccountSetupService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class ClientCompanyUserAccountController extends Controller
{
    public function store(
        Request $request,
        Company $company,
        AccountSetupService $accountSetup
    ): RedirectResponse {
        $this->authorizeOwner($request);
        $this->ensureClientCompany($company);

        $request->merge([
            'email' => Str::lower(trim((string) $request->input('email'))),
        ]);

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255'],
            'account_role' => ['required', Rule::in(User::CLIENT_ROLES)],
        ]);

        [$user, $wasCreated] = DB::transaction(function () use ($accountSetup, $company, $validated): array {
            $existingUser = User::query()
                ->whereRaw('LOWER(email) = ?', [$validated['email']])
                ->lockForUpdate()
                ->first();

            if ($existingUser !== null) {
                if ((int) $existingUser->company_id === $company->id) {
                    throw ValidationException::withMessages([
                        'email' => 'This user already exists in this client company.',
                    ]);
                }

                if ($existingUser->company_id !== null) {
                    throw ValidationException::withMessages([
                        'email' => 'This email already belongs to another company and was not transferred.',
                    ]);
                }

                if (! $existingUser->isEligibleForClientAssignment()) {
                    throw ValidationException::withMessages([
                        'email' => 'This existing account is not eligible for client-company assignment.',
                    ]);
                }

                $existingUser->forceFill([
                    'company_id' => $company->id,
                    'role' => $validated['account_role'],
                ])->save();

                return [$existingUser, false];
            }

            $user = User::create([
                'name' => $validated['name'],
                'email' => $validated['email'],
                'password' => $accountSetup->randomUnusablePasswordHash(),
                'company_id' => $company->id,
                'role' => $validated['account_role'],
            ]);

            return [$user, true];
        });

        if (! $wasCreated) {
            return back()->with('success', 'Existing unassigned account linked to this client company.');
        }

        $setupUrl = $accountSetup->issue($user);
        $response = back()->with('success', 'Client account created and a secure account-setup link was issued.');

        if (app()->environment(['local', 'testing'])) {
            $response->with('account_setup_url', $setupUrl);
        }

        return $response;
    }

    private function authorizeOwner(Request $request): void
    {
        abort_unless($request->user()?->hasPlatformOwnerAccess(), 403);
    }

    private function ensureClientCompany(Company $company): void
    {
        abort_unless($company->type === Company::TYPE_CLIENT, 404);
    }
}
