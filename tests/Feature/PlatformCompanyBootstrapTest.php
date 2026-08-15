<?php

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use Database\Seeders\PlatformCompanySeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class PlatformCompanyBootstrapTest extends TestCase
{
    use RefreshDatabase;

    public function test_command_idempotently_configures_only_explicit_platform_operators(): void
    {
        $operator = User::factory()->create([
            'email' => 'operator@example.test',
            'role' => User::LEGACY_ROLE_ADMIN,
            'company_id' => null,
        ]);
        $unclassifiedUser = User::factory()->create([
            'email' => 'unclassified@example.test',
            'role' => User::LEGACY_ROLE_USER,
            'company_id' => null,
        ]);

        $arguments = [
            '--name' => 'Example Security Platform',
            '--domain' => 'security.example.test',
            '--owner-email' => [$operator->email],
        ];

        $this->artisan('platform:bootstrap', $arguments)
            ->expectsOutputToContain('Platform company created')
            ->expectsOutputToContain("Configured platform operator: {$operator->email} as platform_owner")
            ->assertSuccessful();

        $company = Company::query()->sole();

        $this->assertSame(Company::TYPE_PLATFORM, $company->type);
        $this->assertSame(Company::STATUS_ACTIVE, $company->status);
        $this->assertTrue($company->is_active);
        $this->assertSame($company->id, $operator->fresh()->company_id);
        $this->assertSame(User::ROLE_PLATFORM_OWNER, $operator->fresh()->role);
        $this->assertNull($unclassifiedUser->fresh()->company_id);
        $this->assertSame(User::LEGACY_ROLE_USER, $unclassifiedUser->fresh()->role);

        $this->artisan('platform:bootstrap', $arguments)
            ->expectsOutputToContain('Platform company reused')
            ->expectsOutputToContain("Already configured: {$operator->email} as platform_owner")
            ->assertSuccessful();

        $this->assertSame(1, Company::query()->where('type', Company::TYPE_PLATFORM)->count());
    }

    public function test_command_does_not_assign_missing_non_admin_or_already_tenanted_users(): void
    {
        $clientCompany = Company::create([
            'name' => 'Existing Client',
            'domain' => 'client.example.test',
            'type' => Company::TYPE_CLIENT,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
        $nonAdmin = User::factory()->create([
            'email' => 'member@example.test',
            'role' => User::LEGACY_ROLE_USER,
            'company_id' => null,
        ]);
        $clientAdmin = User::factory()->create([
            'email' => 'client-admin@example.test',
            'role' => User::ROLE_CLIENT_ADMIN,
            'company_id' => $clientCompany->id,
        ]);

        $this->artisan('platform:bootstrap', [
            '--name' => 'Example Security Platform',
            '--domain' => 'security.example.test',
            '--owner-email' => [
                'missing@example.test',
                $nonAdmin->email,
                $clientAdmin->email,
            ],
        ])
            ->expectsOutputToContain('Requested operator was not found and was not created')
            ->expectsOutputToContain('has role user and was not promoted to platform_owner')
            ->expectsOutputToContain('already belongs to company')
            ->assertFailed();

        $this->assertNull($nonAdmin->fresh()->company_id);
        $this->assertSame($clientCompany->id, $clientAdmin->fresh()->company_id);
        $this->assertSame(1, Company::query()->where('type', Company::TYPE_PLATFORM)->count());
    }

    public function test_configured_seeder_is_idempotent_and_never_creates_default_users(): void
    {
        $operator = User::factory()->create([
            'email' => 'seeded-operator@example.test',
            'role' => User::LEGACY_ROLE_ADMIN,
            'company_id' => null,
        ]);
        $userCount = User::query()->count();

        config()->set('platform.company.name', 'Seeded Security Platform');
        config()->set('platform.company.domain', 'seeded.example.test');
        config()->set('platform.operator_roles', [
            $operator->email => User::ROLE_PLATFORM_STAFF,
        ]);

        $this->seed(PlatformCompanySeeder::class);
        $this->seed(PlatformCompanySeeder::class);

        $this->assertSame(1, Company::query()->where('type', Company::TYPE_PLATFORM)->count());
        $this->assertSame($userCount, User::query()->count());
        $this->assertSame(Company::query()->sole()->id, $operator->fresh()->company_id);
        $this->assertSame(User::ROLE_PLATFORM_STAFF, $operator->fresh()->role);
    }

    public function test_bootstrap_refuses_to_create_a_second_platform_company(): void
    {
        Company::create([
            'name' => 'Existing Platform',
            'domain' => 'existing-platform.example.test',
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);

        $this->artisan('platform:bootstrap', [
            '--name' => 'Different Platform',
            '--domain' => 'different-platform.example.test',
        ])
            ->expectsOutputToContain('The platform company already uses domain')
            ->assertFailed();

        $this->assertSame(1, Company::query()->where('type', Company::TYPE_PLATFORM)->count());
    }
}
