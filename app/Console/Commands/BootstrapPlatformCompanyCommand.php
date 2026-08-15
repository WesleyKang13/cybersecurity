<?php

namespace App\Console\Commands;

use App\Models\User;
use App\Services\PlatformCompanyBootstrapper;
use Illuminate\Console\Command;
use InvalidArgumentException;
use Throwable;

class BootstrapPlatformCompanyCommand extends Command
{
    protected $signature = 'platform:bootstrap
        {--name= : Platform company name; falls back to PLATFORM_COMPANY_NAME}
        {--domain= : Stable platform company domain; falls back to PLATFORM_COMPANY_DOMAIN}
        {--owner-email=* : Existing legacy admin to assign as platform owner; repeat as needed}
        {--staff-email=* : Existing legacy admin to assign as platform staff; repeat as needed}';

    protected $description = 'Idempotently create the platform company and assign explicitly named existing admin users';

    public function handle(PlatformCompanyBootstrapper $bootstrapper): int
    {
        $name = trim((string) ($this->option('name') ?: config('platform.company.name')));
        $domain = trim((string) ($this->option('domain') ?: config('platform.company.domain')));

        if ($name === '' || $domain === '') {
            $this->error(
                'Provide --name and --domain, or configure PLATFORM_COMPANY_NAME and PLATFORM_COMPANY_DOMAIN.'
            );

            return self::FAILURE;
        }

        try {
            $operatorRoles = $this->operatorRoles();
            $result = $bootstrapper->bootstrap($name, $domain, $operatorRoles);
        } catch (Throwable $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $action = $result['company_created'] ? 'created' : 'reused';
        $this->info("Platform company {$action}: {$result['company']->name} ({$result['company']->domain}).");

        foreach ($result['assigned'] as $email) {
            $this->info("Configured platform operator: {$email} as {$operatorRoles[$email]}");
        }

        foreach ($result['already_assigned'] as $email) {
            $this->line("Already configured: {$email} as {$operatorRoles[$email]}");
        }

        foreach ($result['missing'] as $email) {
            $this->warn("Requested operator was not found and was not created: {$email}");
        }

        foreach ($result['ineligible_roles'] as $ineligible) {
            $this->warn(
                "Requested operator {$ineligible['email']} has role {$ineligible['current_role']} and was not promoted to {$ineligible['requested_role']}."
            );
        }

        foreach ($result['conflicts'] as $conflict) {
            $this->warn(
                "Requested operator {$conflict['email']} already belongs to company {$conflict['company_id']} and was not reassigned."
            );
        }

        $unassignedUsers = User::query()
            ->whereNull('company_id')
            ->orderBy('id')
            ->get(['id', 'email', 'role']);

        if ($unassignedUsers->isNotEmpty()) {
            $this->warn('Users still awaiting explicit company classification:');
            $this->table(
                ['ID', 'Email', 'Current role'],
                $unassignedUsers->map(fn (User $user): array => [
                    $user->id,
                    $user->email,
                    $user->role,
                ])->all()
            );
        }

        $hasAssignmentProblems = $result['missing'] !== []
            || $result['ineligible_roles'] !== []
            || $result['conflicts'] !== [];

        return $hasAssignmentProblems ? self::FAILURE : self::SUCCESS;
    }

    /**
     * @return array<string, string>
     */
    private function operatorRoles(): array
    {
        $ownerEmails = (array) $this->option('owner-email');
        $staffEmails = (array) $this->option('staff-email');

        if ($ownerEmails === [] && $staffEmails === []) {
            return (array) config('platform.operator_roles', []);
        }

        $operatorRoles = [];

        foreach ($ownerEmails as $email) {
            $operatorRoles[strtolower(trim((string) $email))] = User::ROLE_PLATFORM_OWNER;
        }

        foreach ($staffEmails as $email) {
            $email = strtolower(trim((string) $email));

            if (isset($operatorRoles[$email])) {
                throw new InvalidArgumentException("Platform operator {$email} cannot be both owner and staff.");
            }

            $operatorRoles[$email] = User::ROLE_PLATFORM_STAFF;
        }

        return $operatorRoles;
    }
}
