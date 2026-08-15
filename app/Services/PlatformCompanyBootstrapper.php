<?php

namespace App\Services;

use App\Models\Company;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use LogicException;

class PlatformCompanyBootstrapper
{
    /**
     * @param  array<string, string>  $operatorRoles
     * @return array{
     *     company: Company,
     *     company_created: bool,
     *     assigned: array<int, string>,
     *     already_assigned: array<int, string>,
     *     missing: array<int, string>,
     *     ineligible_roles: array<int, array{email: string, current_role: string|null, requested_role: string}>,
     *     conflicts: array<int, array{email: string, company_id: int|null}>
     * }
     */
    public function bootstrap(string $name, string $domain, array $operatorRoles = []): array
    {
        $name = trim($name);
        $domain = strtolower(trim($domain));
        $normalizedOperatorRoles = [];

        if ($name === '') {
            throw new InvalidArgumentException('A platform company name is required.');
        }

        if ($domain === '') {
            throw new InvalidArgumentException('A stable platform company domain is required.');
        }

        foreach ($operatorRoles as $email => $role) {
            $email = strtolower(trim((string) $email));
            $role = trim((string) $role);

            if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                throw new InvalidArgumentException("Invalid platform operator email: {$email}");
            }

            if (! in_array($role, [User::ROLE_PLATFORM_OWNER, User::ROLE_PLATFORM_STAFF], true)) {
                throw new InvalidArgumentException("Invalid platform operator role for {$email}: {$role}");
            }

            if (isset($normalizedOperatorRoles[$email]) && $normalizedOperatorRoles[$email] !== $role) {
                throw new InvalidArgumentException("Platform operator {$email} was assigned conflicting roles.");
            }

            $normalizedOperatorRoles[$email] = $role;
        }

        return DB::transaction(function () use ($name, $domain, $normalizedOperatorRoles): array {
            $platformCompanies = Company::query()
                ->where('type', Company::TYPE_PLATFORM)
                ->lockForUpdate()
                ->get();

            if ($platformCompanies->count() > 1) {
                throw new LogicException('Multiple platform companies already exist; bootstrap stopped without making assignments.');
            }

            $company = $platformCompanies->first();
            $companyCreated = false;

            if ($company !== null) {
                $existingDomain = strtolower(trim((string) $company->domain));

                if ($existingDomain !== '' && $existingDomain !== $domain) {
                    throw new LogicException(
                        "The platform company already uses domain {$company->domain}; refusing to create or replace it with {$domain}."
                    );
                }
            } else {
                $companyUsingDomain = Company::query()
                    ->whereRaw('LOWER(domain) = ?', [$domain])
                    ->lockForUpdate()
                    ->first();

                if ($companyUsingDomain !== null) {
                    throw new LogicException(
                        "The domain {$domain} already belongs to a non-platform company; bootstrap stopped."
                    );
                }

                $company = new Company;
                $companyCreated = true;
            }

            $company->fill([
                'name' => $name,
                'domain' => $domain,
                'type' => Company::TYPE_PLATFORM,
                'status' => Company::STATUS_ACTIVE,
                'is_active' => true,
            ]);
            $company->save();

            $result = [
                'company' => $company,
                'company_created' => $companyCreated,
                'assigned' => [],
                'already_assigned' => [],
                'missing' => [],
                'ineligible_roles' => [],
                'conflicts' => [],
            ];

            foreach ($normalizedOperatorRoles as $email => $requestedRole) {
                if (! User::isRoleValidForCompany($requestedRole, $company)) {
                    throw new LogicException("Role {$requestedRole} is not valid for the platform company.");
                }

                $user = User::query()
                    ->whereRaw('LOWER(email) = ?', [$email])
                    ->lockForUpdate()
                    ->first();

                if ($user === null) {
                    $result['missing'][] = $email;

                    continue;
                }

                if ($user->company_id !== null && (int) $user->company_id !== (int) $company->getKey()) {
                    $result['conflicts'][] = [
                        'email' => $email,
                        'company_id' => (int) $user->company_id,
                    ];

                    continue;
                }

                if ($user->role === User::LEGACY_ROLE_ADMIN) {
                    $user->update([
                        'company_id' => $company->getKey(),
                        'role' => $requestedRole,
                    ]);
                    $result['assigned'][] = $email;

                    continue;
                }

                if ($user->role === $requestedRole) {
                    if ($user->company_id === null) {
                        $user->update(['company_id' => $company->getKey()]);
                        $result['assigned'][] = $email;
                    } else {
                        $result['already_assigned'][] = $email;
                    }

                    continue;
                }

                $result['ineligible_roles'][] = [
                    'email' => $email,
                    'current_role' => $user->role,
                    'requested_role' => $requestedRole,
                ];
            }

            return $result;
        });
    }
}
