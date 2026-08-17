<?php

declare(strict_types=1);

namespace App\Http\Controllers\Platform;

use App\Http\Controllers\Controller;
use App\Models\Company;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Inertia\Inertia;
use Inertia\Response;

class ClientCompanyController extends Controller
{
    public function index(Request $request): Response
    {
        $this->authorizeOwner($request);

        return Inertia::render('Platform/ClientCompanies/Index', [
            'companies' => Company::query()
                ->where('type', Company::TYPE_CLIENT)
                ->withCount('users')
                ->orderBy('name')
                ->get(['id', 'name', 'domain', 'type', 'status', 'is_active', 'created_at']),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $this->authorizeOwner($request);
        $this->normalizeDomain($request);

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'domain' => ['nullable', 'string', 'max:255', Rule::unique('companies', 'domain')],
            'status' => ['required', Rule::in([
                Company::STATUS_ACTIVE,
                Company::STATUS_INACTIVE,
            ])],
        ]);

        $company = Company::create([
            'name' => $validated['name'],
            'domain' => ($validated['domain'] ?? null) ?: null,
            'type' => Company::TYPE_CLIENT,
            'status' => $validated['status'],
            'is_active' => $validated['status'] === Company::STATUS_ACTIVE,
        ]);

        return to_route('platform.client-companies.show', $company)
            ->with('success', 'Client company created.');
    }

    public function show(Request $request, Company $company): Response
    {
        $this->authorizeOwner($request);
        $this->ensureClientCompany($company);

        $company->load(['users' => fn ($query) => $query
            ->select(['id', 'company_id', 'name', 'email', 'role', 'created_at'])
            ->orderBy('name')]);

        return Inertia::render('Platform/ClientCompanies/Show', [
            'company' => $company->only([
                'id',
                'name',
                'domain',
                'type',
                'status',
                'is_active',
                'created_at',
            ]) + ['users' => $company->users],
            'eligibleUsers' => User::query()
                ->whereNull('company_id')
                ->whereIn('role', User::CLIENT_ASSIGNABLE_TRANSITIONAL_ROLES)
                ->orderBy('name')
                ->get(['id', 'name', 'email', 'role']),
            'clientRoles' => User::CLIENT_ROLES,
        ]);
    }

    public function update(Request $request, Company $company): RedirectResponse
    {
        $this->authorizeOwner($request);
        $this->ensureClientCompany($company);
        $this->normalizeDomain($request);

        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'domain' => [
                'nullable',
                'string',
                'max:255',
                Rule::unique('companies', 'domain')->ignore($company->id),
            ],
            'status' => ['required', Rule::in([
                Company::STATUS_ACTIVE,
                Company::STATUS_INACTIVE,
            ])],
        ]);

        $company->update([
            'name' => $validated['name'],
            'domain' => ($validated['domain'] ?? null) ?: null,
            'status' => $validated['status'],
            'is_active' => $validated['status'] === Company::STATUS_ACTIVE,
        ]);

        return back()->with('success', 'Client company updated.');
    }

    private function authorizeOwner(Request $request): void
    {
        abort_unless($request->user()?->hasPlatformOwnerAccess(), 403);
    }

    private function ensureClientCompany(Company $company): void
    {
        abort_unless($company->type === Company::TYPE_CLIENT, 404);
    }

    private function normalizeDomain(Request $request): void
    {
        if ($request->filled('domain')) {
            $request->merge(['domain' => strtolower(trim((string) $request->input('domain')))]);
        }
    }
}
