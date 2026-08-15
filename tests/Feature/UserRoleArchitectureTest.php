<?php

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class UserRoleArchitectureTest extends TestCase
{
    use RefreshDatabase;

    public function test_canonical_role_helpers_recognize_each_role(): void
    {
        $owner = new User(['role' => User::ROLE_PLATFORM_OWNER]);
        $staff = new User(['role' => User::ROLE_PLATFORM_STAFF]);
        $clientAdmin = new User(['role' => User::ROLE_CLIENT_ADMIN]);
        $clientUser = new User(['role' => User::ROLE_CLIENT_USER]);

        $this->assertTrue($owner->isPlatformOwner());
        $this->assertTrue($owner->isPlatformUser());
        $this->assertTrue($staff->isPlatformStaff());
        $this->assertTrue($staff->isPlatformUser());
        $this->assertTrue($clientAdmin->isClientAdmin());
        $this->assertTrue($clientUser->isClientUser());
    }

    public function test_roles_are_compatible_only_with_their_company_type(): void
    {
        $platform = new Company(['type' => Company::TYPE_PLATFORM]);
        $client = new Company(['type' => Company::TYPE_CLIENT]);

        $this->assertTrue(User::isRoleValidForCompany(User::ROLE_PLATFORM_OWNER, $platform));
        $this->assertTrue(User::isRoleValidForCompany(User::ROLE_PLATFORM_STAFF, $platform));
        $this->assertTrue(User::isRoleValidForCompany(User::ROLE_CLIENT_ADMIN, $client));
        $this->assertTrue(User::isRoleValidForCompany(User::ROLE_CLIENT_USER, $client));

        $this->assertFalse(User::isRoleValidForCompany(User::ROLE_CLIENT_ADMIN, $platform));
        $this->assertFalse(User::isRoleValidForCompany(User::ROLE_CLIENT_USER, $platform));
        $this->assertFalse(User::isRoleValidForCompany(User::ROLE_PLATFORM_OWNER, $client));
        $this->assertFalse(User::isRoleValidForCompany(User::ROLE_PLATFORM_STAFF, $client));
        $this->assertFalse(User::isRoleValidForCompany(User::LEGACY_ROLE_ADMIN, $platform));
        $this->assertFalse(User::isRoleValidForCompany(User::ROLE_CLIENT_USER, null));
    }

    public function test_client_roles_are_never_treated_as_platform_admins(): void
    {
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT);
        $clientAdmin = User::factory()->create([
            'company_id' => $clientCompany->id,
            'role' => User::ROLE_CLIENT_ADMIN,
        ]);
        $clientUser = User::factory()->create([
            'company_id' => $clientCompany->id,
            'role' => User::ROLE_CLIENT_USER,
        ]);

        $this->assertFalse($clientAdmin->isAdmin());
        $this->assertFalse($clientUser->isAdmin());
        $this->actingAs($clientAdmin)->get(route('admin.dashboard'))->assertForbidden();
        $this->actingAs($clientUser)->get(route('admin.dashboard'))->assertForbidden();
    }

    public function test_platform_owner_and_staff_retain_existing_admin_access(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = User::factory()->create([
            'company_id' => $platformCompany->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);
        $staff = User::factory()->create([
            'company_id' => $platformCompany->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);

        $this->assertTrue($owner->isAdmin());
        $this->assertTrue($staff->isAdmin());
        $this->actingAs($owner)->get(route('admin.dashboard'))->assertOk();
        $this->actingAs($staff)->get(route('admin.dashboard'))->assertOk();
    }

    public function test_platform_role_on_a_client_company_does_not_grant_admin_access(): void
    {
        $user = User::factory()->create([
            'company_id' => $this->createCompany(Company::TYPE_CLIENT)->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);

        $this->assertFalse($user->isAdmin());
        $this->actingAs($user)->get(route('admin.dashboard'))->assertForbidden();
    }

    public function test_admin_user_update_rejects_role_incompatible_with_company(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = User::factory()->create([
            'company_id' => $platformCompany->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);
        $staff = User::factory()->create([
            'company_id' => $platformCompany->id,
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);

        $this->actingAs($owner)->put(route('admin.users.update', $staff), [
            'name' => $staff->name,
            'email' => $staff->email,
            'role' => User::ROLE_CLIENT_ADMIN,
        ])->assertSessionHasErrors('role');

        $this->assertSame(User::ROLE_PLATFORM_STAFF, $staff->fresh()->role);
    }

    public function test_unassigned_legacy_user_can_authenticate_without_platform_access(): void
    {
        $user = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $response = $this->post('/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

        $this->assertAuthenticatedAs($user);
        $this->assertFalse($user->isAdmin());
        $response->assertRedirect(route('dashboard', absolute: false));
    }

    private function createCompany(string $type): Company
    {
        return Company::create([
            'name' => fake()->company(),
            'domain' => fake()->unique()->domainName(),
            'type' => $type,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
        ]);
    }
}
