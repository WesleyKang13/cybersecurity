<?php

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class CompanyTenantArchitectureTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_belongs_to_a_company_and_company_has_many_users(): void
    {
        $company = $this->createCompany();
        $users = User::factory()->count(2)->create(['company_id' => $company->id]);

        $this->assertTrue($users->first()->company->is($company));
        $this->assertCount(2, $company->fresh()->users);
        $this->assertTrue($company->users->contains($users->last()));
    }

    public function test_company_type_and_status_have_safe_defaults_and_accept_supported_values(): void
    {
        $client = $this->createCompany();
        $platform = $this->createCompany([
            'name' => 'Platform Security Company',
            'type' => Company::TYPE_PLATFORM,
            'status' => Company::STATUS_INACTIVE,
        ]);

        $this->assertSame(Company::TYPE_CLIENT, $client->fresh()->type);
        $this->assertSame(Company::STATUS_ACTIVE, $client->fresh()->status);
        $this->assertSame(Company::TYPE_PLATFORM, $platform->fresh()->type);
        $this->assertSame(Company::STATUS_INACTIVE, $platform->fresh()->status);
    }

    public function test_user_with_a_company_can_still_authenticate(): void
    {
        $user = User::factory()->create(['company_id' => $this->createCompany()->id]);

        $response = $this->post('/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $this->assertAuthenticatedAs($user);
        $response->assertRedirect(route('dashboard', absolute: false));
    }

    public function test_admin_created_user_inherits_canonical_company_id(): void
    {
        $adminCompany = $this->createCompany(['type' => Company::TYPE_PLATFORM]);
        $otherCompany = $this->createCompany();
        $admin = User::factory()->create([
            'company_id' => $adminCompany->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);

        $response = $this->actingAs($admin)->post(route('admin.users.store'), [
            'name' => 'Managed User',
            'email' => 'managed@example.test',
            'company_id' => $otherCompany->id,
        ]);

        $response->assertRedirect();
        $this->assertDatabaseHas('users', [
            'email' => 'managed@example.test',
            'company_id' => $adminCompany->id,
            'organization_id' => null,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
    }

    public function test_admin_can_update_only_users_in_the_same_company(): void
    {
        $adminCompany = $this->createCompany(['type' => Company::TYPE_PLATFORM]);
        $otherCompany = $this->createCompany();
        $admin = User::factory()->create([
            'company_id' => $adminCompany->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);
        $companyUser = User::factory()->create([
            'company_id' => $adminCompany->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
        $otherUser = User::factory()->create([
            'company_id' => $otherCompany->id,
            'role' => User::ROLE_CLIENT_USER,
        ]);

        $this->actingAs($admin)->put(route('admin.users.update', $companyUser), [
            'name' => 'Updated User',
            'email' => $companyUser->email,
            'role' => User::ROLE_PLATFORM_STAFF,
            'company_id' => $otherCompany->id,
        ])->assertRedirect();

        $this->assertDatabaseHas('users', [
            'id' => $companyUser->id,
            'company_id' => $adminCompany->id,
            'name' => 'Updated User',
        ]);

        $this->actingAs($admin)->put(route('admin.users.update', $otherUser), [
            'name' => 'Unauthorized Update',
            'email' => $otherUser->email,
            'role' => User::ROLE_CLIENT_USER,
        ])->assertForbidden();
    }

    public function test_admin_dashboard_lists_only_users_in_the_admin_company(): void
    {
        $adminCompany = $this->createCompany(['type' => Company::TYPE_PLATFORM]);
        $otherCompany = $this->createCompany();
        $admin = User::factory()->create([
            'company_id' => $adminCompany->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);
        User::factory()->create([
            'company_id' => $adminCompany->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
        User::factory()->create([
            'company_id' => $otherCompany->id,
            'role' => User::ROLE_CLIENT_USER,
        ]);

        $this->actingAs($admin)
            ->get(route('admin.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Dashboard')
                ->has('users', 2));
    }

    public function test_legacy_organization_id_is_backfilled_only_when_it_matches_a_company(): void
    {
        $canonicalCompany = $this->createCompany();
        $otherCompany = $this->createCompany();
        $matchableUser = User::factory()->create(['company_id' => null]);
        $unmatchedUser = User::factory()->create(['company_id' => null]);
        $conflictingUser = User::factory()->create(['company_id' => $canonicalCompany->id]);

        DB::table('users')->where('id', $matchableUser->id)->update([
            'organization_id' => $canonicalCompany->id,
        ]);
        DB::table('users')->where('id', $unmatchedUser->id)->update([
            'organization_id' => 999999,
        ]);
        DB::table('users')->where('id', $conflictingUser->id)->update([
            'organization_id' => $otherCompany->id,
        ]);

        $migration = require database_path('migrations/2026_08_15_130000_add_company_tenant_fields_and_backfill_users.php');
        $migration->up();

        $this->assertSame($canonicalCompany->id, $matchableUser->fresh()->company_id);
        $this->assertNull($unmatchedUser->fresh()->company_id);
        $this->assertSame($canonicalCompany->id, $conflictingUser->fresh()->company_id);
    }

    private function createCompany(array $attributes = []): Company
    {
        return Company::create(array_merge([
            'name' => 'Client Company '.fake()->unique()->numerify('####'),
            'domain' => fake()->unique()->domainName(),
            'is_active' => true,
        ], $attributes));
    }
}
