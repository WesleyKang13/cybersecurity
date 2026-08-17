<?php

declare(strict_types=1);

namespace App\Http\Controllers\Platform;

use App\Http\Controllers\Controller;
use App\Models\Company;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class ClientCompanyUserController extends Controller
{
    public function store(Request $request, Company $company): RedirectResponse
    {
        $this->authorizeOwner($request);
        $this->ensureClientCompany($company);

        $validated = $request->validate([
            'user_id' => ['required', 'integer', Rule::exists('users', 'id')],
            'role' => ['required', Rule::in(User::CLIENT_ROLES)],
        ]);

        DB::transaction(function () use ($company, $validated): void {
            $user = User::query()->lockForUpdate()->findOrFail($validated['user_id']);

            if ($user->company_id !== null) {
                $existingCompany = Company::query()->find($user->company_id);
                $existingCompanyName = $existingCompany?->name ?? 'another company';

                throw ValidationException::withMessages([
                    'user_id' => "This user already belongs to {$existingCompanyName} and was not reassigned.",
                ]);
            }

            if (! $user->isEligibleForClientAssignment()) {
                throw ValidationException::withMessages([
                    'user_id' => 'This account is not eligible for client-company assignment.',
                ]);
            }

            if (! User::isRoleValidForCompany($validated['role'], $company)) {
                throw ValidationException::withMessages([
                    'role' => 'The selected role is not valid for a client company.',
                ]);
            }

            $user->forceFill([
                'company_id' => $company->id,
                'role' => $validated['role'],
            ])->save();
        });

        return back()->with('success', 'Existing user assigned to the client company.');
    }

    public function update(Request $request, Company $company, User $user): RedirectResponse
    {
        $this->authorizeOwner($request);
        $this->ensureClientCompany($company);

        $validated = $request->validate([
            'role' => ['required', Rule::in(User::CLIENT_ROLES)],
        ]);

        DB::transaction(function () use ($company, $user, $validated): void {
            $lockedUser = User::query()->lockForUpdate()->findOrFail($user->id);

            if ((int) $lockedUser->company_id !== $company->id) {
                throw ValidationException::withMessages([
                    'role' => 'This user does not belong to the selected client company.',
                ]);
            }

            if (! in_array($lockedUser->role, User::CLIENT_ROLES, true)) {
                throw ValidationException::withMessages([
                    'role' => 'Only existing client roles can be changed through this workflow.',
                ]);
            }

            if (! User::isRoleValidForCompany($validated['role'], $company)) {
                throw ValidationException::withMessages([
                    'role' => 'The selected role is not valid for a client company.',
                ]);
            }

            $lockedUser->forceFill(['role' => $validated['role']])->save();
        });

        return back()->with('success', 'Client role updated.');
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
