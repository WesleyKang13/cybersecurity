<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

class PlatformAuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_active_platform_owner_and_staff_can_access_dns_security(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);

        $this->assertTrue($owner->hasPlatformOwnerAccess());
        $this->assertTrue($owner->hasPlatformAccess());
        $this->assertTrue($staff->hasPlatformAccess());
        $this->assertFalse($staff->hasPlatformOwnerAccess());

        $this->actingAs($owner)->get(route('dns-security.index'))->assertOk();
        $this->actingAs($staff)->get(route('dns-security.index'))->assertOk();
    }

    public function test_client_legacy_inactive_and_mismatched_users_cannot_access_dns_security(): void
    {
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT);
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $inactivePlatformCompany = $this->createCompany(
            Company::TYPE_PLATFORM,
            Company::STATUS_INACTIVE
        );

        $deniedUsers = [
            $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN),
            $this->createUser($clientCompany, User::ROLE_CLIENT_USER),
            $this->createUser($platformCompany, User::ROLE_CLIENT_ADMIN),
            $this->createUser($clientCompany, User::ROLE_PLATFORM_STAFF),
            $this->createUser($inactivePlatformCompany, User::ROLE_PLATFORM_OWNER),
            User::factory()->create([
                'company_id' => null,
                'role' => User::LEGACY_ROLE_USER,
            ]),
        ];

        foreach ($deniedUsers as $user) {
            $this->assertFalse($user->hasPlatformAccess());
            $this->actingAs($user)->get(route('dns-security.index'))->assertForbidden();
        }
    }

    public function test_owner_and_staff_can_access_platform_security_operations_but_client_roles_cannot(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platformCompany, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($platformCompany, User::ROLE_PLATFORM_STAFF);
        $clientAdmin = $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN);
        $clientUser = $this->createUser($clientCompany, User::ROLE_CLIENT_USER);

        $this->actingAs($owner)->get(route('admin.dashboard'))->assertOk();
        $this->actingAs($staff)->get(route('admin.dashboard'))->assertOk();
        $this->actingAs($staff)->get(route('admin.blocked-ips.index'))->assertOk();
        $this->actingAs($clientAdmin)->get(route('admin.dashboard'))->assertForbidden();
        $this->actingAs($clientUser)->get(route('admin.blocked-ips.index'))->assertForbidden();
    }

    public function test_platform_owner_can_create_staff_and_posted_role_cannot_create_an_owner(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)->post(route('admin.users.store'), [
            'name' => 'New Platform User',
            'email' => 'new-staff@example.test',
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertRedirect();

        $this->assertDatabaseHas('users', [
            'company_id' => $company->id,
            'email' => 'new-staff@example.test',
            'role' => User::ROLE_PLATFORM_STAFF,
        ]);
    }

    public function test_platform_owner_can_promote_platform_staff(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);

        $this->actingAs($owner)->put(route('admin.users.update', $staff), [
            'name' => $staff->name,
            'email' => $staff->email,
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertRedirect();

        $this->assertSame(User::ROLE_PLATFORM_OWNER, $staff->fresh()->role);
    }

    public function test_platform_staff_cannot_create_promote_or_modify_platform_accounts(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);
        $otherStaff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);

        $this->actingAs($staff)->post(route('admin.users.store'), [
            'name' => 'Illicit Owner',
            'email' => 'illicit-owner@example.test',
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertForbidden();

        $this->actingAs($staff)->put(route('admin.users.update', $staff), [
            'name' => $staff->name,
            'email' => $staff->email,
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertForbidden();

        $this->actingAs($staff)->put(route('admin.users.update', $otherStaff), [
            'name' => $otherStaff->name,
            'email' => $otherStaff->email,
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertForbidden();

        $this->actingAs($staff)->put(route('admin.users.update', $owner), [
            'name' => 'Modified Owner',
            'email' => $owner->email,
            'role' => User::ROLE_PLATFORM_STAFF,
        ])->assertForbidden();

        $this->assertDatabaseMissing('users', ['email' => 'illicit-owner@example.test']);
        $this->assertSame(User::ROLE_PLATFORM_STAFF, $staff->fresh()->role);
        $this->assertSame(User::ROLE_PLATFORM_STAFF, $otherStaff->fresh()->role);
        $this->assertSame(User::ROLE_PLATFORM_OWNER, $owner->fresh()->role);
        $this->assertNotSame('Modified Owner', $owner->fresh()->name);
    }

    public function test_last_platform_owner_cannot_be_demoted(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)->put(route('admin.users.update', $owner), [
            'name' => $owner->name,
            'email' => $owner->email,
            'role' => User::ROLE_PLATFORM_STAFF,
        ])->assertSessionHasErrors('role');

        $this->assertSame(User::ROLE_PLATFORM_OWNER, $owner->fresh()->role);
    }

    public function test_last_platform_owner_cannot_delete_their_own_account(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)->delete(route('profile.destroy'), [
            'password' => 'password',
        ])->assertSessionHasErrors('password');

        $this->assertAuthenticatedAs($owner);
        $this->assertDatabaseHas('users', ['id' => $owner->id]);
    }

    public function test_platform_owner_can_delete_their_account_when_another_owner_remains(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM);
        $remainingOwner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);
        $departingOwner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($departingOwner)->delete(route('profile.destroy'), [
            'password' => 'password',
        ])->assertRedirect('/');

        $this->assertGuest();
        $this->assertDatabaseMissing('users', ['id' => $departingOwner->id]);
        $this->assertDatabaseHas('users', [
            'id' => $remainingOwner->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);
    }

    public function test_owner_cannot_update_a_user_from_another_company(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $otherCompany = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platformCompany, User::ROLE_PLATFORM_OWNER);
        $clientAdmin = $this->createUser($otherCompany, User::ROLE_CLIENT_ADMIN);

        $this->actingAs($owner)->put(route('admin.users.update', $clientAdmin), [
            'name' => 'Cross-company Update',
            'email' => $clientAdmin->email,
            'role' => User::ROLE_PLATFORM_STAFF,
        ])->assertForbidden();

        $this->assertSame(User::ROLE_CLIENT_ADMIN, $clientAdmin->fresh()->role);
    }

    public function test_global_whitelist_is_manageable_by_platform_users_only(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM);
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT);
        $staff = $this->createUser($platformCompany, User::ROLE_PLATFORM_STAFF);
        $clientAdmin = $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN);
        $legacyUser = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $this->actingAs($staff)->get(route('domains.index'))->assertOk();
        $this->actingAs($staff)->post(route('domains.store'), [
            'domain' => 'trusted.example.test',
            'description' => 'Platform-managed whitelist entry',
        ])->assertRedirect();

        $this->assertDatabaseHas('whitelisted_domains', [
            'domain' => 'trusted.example.test',
            'is_active' => true,
        ]);

        $this->actingAs($clientAdmin)->get(route('domains.index'))->assertForbidden();
        $this->actingAs($legacyUser)->post(route('domains.store'), [
            'domain' => 'unauthorized.example.test',
        ])->assertForbidden();
        $this->assertDatabaseMissing('whitelisted_domains', [
            'domain' => 'unauthorized.example.test',
        ]);
    }

    public function test_legacy_user_keeps_normal_dashboard_sms_profile_and_google_connection_routes(): void
    {
        $legacyUser = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $this->actingAs($legacyUser)->get(route('dashboard'))->assertOk();
        $this->actingAs($legacyUser)->get(route('sms.index'))->assertOk();
        $this->actingAs($legacyUser)->get(route('profile.edit'))->assertOk();
        $this->actingAs($legacyUser)->get(route('google.connect'))->assertRedirect();
    }

    public function test_sensitive_routes_have_explicit_platform_middleware(): void
    {
        $platformRoutes = [
            'dns-security.index',
            'dns-security.store',
            'dns-security.alert-settings',
            'dns-security.block-ip',
            'dns-security.unblock-ip',
            'dns-security.update',
            'dns-security.ip-lookup',
            'dns-security.scan',
            'dns-security.destroy',
            'domains.index',
            'domains.store',
            'domains.update',
            'domains.destroy',
            'admin.dashboard',
            'admin.blocked-ips.index',
            'admin.blocked-ips.destroy',
            'admin.threats.export',
            'admin.ip-intelligence',
            'admin.domains.toggle-status',
            'admin.domains.rotate-token',
            'admin.queue.retry',
        ];

        foreach ($platformRoutes as $routeName) {
            $route = Route::getRoutes()->getByName($routeName);

            $this->assertNotNull($route, "Route [{$routeName}] is not registered.");
            $this->assertContains('platform', $route->gatherMiddleware(), "Route [{$routeName}] is not platform-protected.");
        }

        foreach (['admin.users.store', 'admin.users.update'] as $routeName) {
            $middleware = Route::getRoutes()->getByName($routeName)?->gatherMiddleware() ?? [];

            $this->assertContains('platform', $middleware);
            $this->assertContains('platform.owner', $middleware);
        }
    }

    private function createCompany(string $type, string $status = Company::STATUS_ACTIVE): Company
    {
        return Company::create([
            'name' => fake()->unique()->company(),
            'domain' => fake()->unique()->domainName(),
            'type' => $type,
            'status' => $status,
            'is_active' => $status === Company::STATUS_ACTIVE,
        ]);
    }

    private function createUser(Company $company, string $role): User
    {
        return User::factory()->create([
            'company_id' => $company->id,
            'role' => $role,
        ]);
    }
}
