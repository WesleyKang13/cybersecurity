<?php

namespace Database\Seeders;

use App\Services\PlatformCompanyBootstrapper;
use Illuminate\Database\Seeder;
use RuntimeException;

class PlatformCompanySeeder extends Seeder
{
    public function run(PlatformCompanyBootstrapper $bootstrapper): void
    {
        $name = trim((string) config('platform.company.name'));
        $domain = trim((string) config('platform.company.domain'));

        if ($name === '' || $domain === '') {
            throw new RuntimeException(
                'Set PLATFORM_COMPANY_NAME and PLATFORM_COMPANY_DOMAIN before running the platform company seeder.'
            );
        }

        $operatorRoles = (array) config('platform.operator_roles', []);
        $result = $bootstrapper->bootstrap(
            $name,
            $domain,
            $operatorRoles
        );

        $action = $result['company_created'] ? 'created' : 'reused';
        $this->command?->info("Platform company {$action}: {$result['company']->name}.");

        foreach ($result['assigned'] as $email) {
            $role = $operatorRoles[$email];
            $this->command?->info("Configured platform operator: {$email} as {$role}");
        }

        foreach ($result['already_assigned'] as $email) {
            $role = $operatorRoles[$email];
            $this->command?->line("Already configured: {$email} as {$role}");
        }

        foreach ($result['missing'] as $email) {
            $this->command?->warn("Configured operator was not found and was not created: {$email}");
        }

        foreach ($result['ineligible_roles'] as $ineligible) {
            $this->command?->warn(
                "Configured operator {$ineligible['email']} has an ineligible existing role and was not promoted."
            );
        }

        foreach ($result['conflicts'] as $conflict) {
            $this->command?->warn("Configured operator {$conflict['email']} already belongs to another company.");
        }
    }
}
