<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use App\Support\PortalContext;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ClientCompanyManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_platform_owner_can_list_create_and_view_client_companies(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM, 'CyberSafe Sdn Bhd');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)
            ->get(route('platform.client-companies.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Platform/ClientCompanies/Index')
                ->has('companies', 0)
                ->where('auth.portal.can_manage_platform_users', true));

        $response = $this->post(route('platform.client-companies.store'), [
            'name' => 'Demo Client Ltd',
            'domain' => 'DEMO.EXAMPLE.TEST',
            'status' => Company::STATUS_ACTIVE,
            'type' => Company::TYPE_PLATFORM,
            'is_active' => false,
        ]);

        $company = Company::query()->where('name', 'Demo Client Ltd')->firstOrFail();

        $response->assertRedirect(route('platform.client-companies.show', $company));
        $this->assertSame(Company::TYPE_CLIENT, $company->type);
        $this->assertSame(Company::STATUS_ACTIVE, $company->status);
        $this->assertTrue($company->is_active);
        $this->assertSame('demo.example.test', $company->domain);

        $this->get(route('platform.client-companies.show', $company))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Platform/ClientCompanies/Show')
                ->where('company.id', $company->id)
                ->where('company.type', Company::TYPE_CLIENT)
                ->has('company.users', 0));

        $this->post(route('platform.client-companies.store'), [
            'name' => 'Conflicting Client',
            'domain' => 'demo.example.test',
            'status' => Company::STATUS_ACTIVE,
        ])->assertSessionHasErrors('domain');

        $this->assertDatabaseMissing('companies', ['name' => 'Conflicting Client']);
    }

    public function test_only_an_active_platform_owner_can_manage_client_companies(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $inactivePlatform = $this->createCompany(
            Company::TYPE_PLATFORM,
            status: Company::STATUS_INACTIVE
        );
        $deniedUsers = [
            $this->createUser($platform, User::ROLE_PLATFORM_STAFF),
            $this->createUser($client, User::ROLE_CLIENT_ADMIN),
            $this->createUser($client, User::ROLE_CLIENT_USER),
            $this->createUser($inactivePlatform, User::ROLE_PLATFORM_OWNER),
            User::factory()->create([
                'company_id' => null,
                'role' => User::LEGACY_ROLE_USER,
            ]),
        ];

        foreach ($deniedUsers as $user) {
            $this->actingAs($user)
                ->get(route('platform.client-companies.index'))
                ->assertForbidden();

            $this->actingAs($user)
                ->post(route('platform.client-companies.store'), [
                    'name' => 'Unauthorized Company',
                    'status' => Company::STATUS_ACTIVE,
                ])
                ->assertForbidden();
        }

        $this->assertDatabaseMissing('companies', ['name' => 'Unauthorized Company']);
    }

    public function test_owner_can_update_and_deactivate_a_client_but_not_the_platform_company(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $client = $this->createCompany(Company::TYPE_CLIENT, 'Old Client Name');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)
            ->patch(route('platform.client-companies.update', $client), [
                'name' => 'Renamed Client',
                'domain' => 'renamed.example.test',
                'status' => Company::STATUS_INACTIVE,
                'type' => Company::TYPE_PLATFORM,
                'is_active' => true,
            ])
            ->assertRedirect();

        $client->refresh();
        $this->assertSame('Renamed Client', $client->name);
        $this->assertSame(Company::TYPE_CLIENT, $client->type);
        $this->assertSame(Company::STATUS_INACTIVE, $client->status);
        $this->assertFalse($client->is_active);

        $this->patch(route('platform.client-companies.update', $platform), [
            'name' => 'Compromised Platform',
            'domain' => $platform->domain,
            'status' => Company::STATUS_INACTIVE,
        ])->assertNotFound();

        $this->assertSame('Platform Company', $platform->fresh()->name);
        $this->assertSame(Company::TYPE_PLATFORM, $platform->fresh()->type);
        $this->assertSame(Company::STATUS_ACTIVE, $platform->fresh()->status);
    }

    public function test_owner_can_assign_eligible_unassigned_users_to_client_roles(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT, 'Demo Client Ltd');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $legacyUser = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);
        $legacyMember = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_MEMBER,
        ]);

        $this->actingAs($owner)
            ->post(route('platform.client-companies.users.store', $client), [
                'user_id' => $legacyUser->id,
                'role' => User::ROLE_CLIENT_ADMIN,
                'company_id' => $platform->id,
            ])
            ->assertRedirect();

        $this->post(route('platform.client-companies.users.store', $client), [
            'user_id' => $legacyMember->id,
            'role' => User::ROLE_CLIENT_USER,
        ])->assertRedirect();

        $this->assertDatabaseHas('users', [
            'id' => $legacyUser->id,
            'company_id' => $client->id,
            'role' => User::ROLE_CLIENT_ADMIN,
        ]);
        $this->assertDatabaseHas('users', [
            'id' => $legacyMember->id,
            'company_id' => $client->id,
            'role' => User::ROLE_CLIENT_USER,
        ]);
    }

    public function test_platform_accounts_and_platform_roles_cannot_be_assigned_to_a_client(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($platform, User::ROLE_PLATFORM_STAFF);
        $unassigned = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        foreach ([$owner, $staff] as $platformUser) {
            $this->actingAs($owner)
                ->post(route('platform.client-companies.users.store', $client), [
                    'user_id' => $platformUser->id,
                    'role' => User::ROLE_CLIENT_USER,
                ])
                ->assertSessionHasErrors('user_id');

            $this->assertSame($platform->id, $platformUser->fresh()->company_id);
        }

        foreach ([User::ROLE_PLATFORM_OWNER, User::ROLE_PLATFORM_STAFF] as $platformRole) {
            $this->post(route('platform.client-companies.users.store', $client), [
                'user_id' => $unassigned->id,
                'role' => $platformRole,
            ])->assertSessionHasErrors('role');
        }

        $this->assertNull($unassigned->fresh()->company_id);
        $this->assertSame(User::LEGACY_ROLE_USER, $unassigned->fresh()->role);
    }

    public function test_existing_client_assignment_is_never_silently_replaced(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $firstClient = $this->createCompany(Company::TYPE_CLIENT, 'First Client');
        $secondClient = $this->createCompany(Company::TYPE_CLIENT, 'Second Client');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $existingClientUser = $this->createUser($firstClient, User::ROLE_CLIENT_USER);

        $this->actingAs($owner)
            ->post(route('platform.client-companies.users.store', $secondClient), [
                'user_id' => $existingClientUser->id,
                'role' => User::ROLE_CLIENT_ADMIN,
            ])
            ->assertSessionHasErrors('user_id');

        $existingClientUser->refresh();
        $this->assertSame($firstClient->id, $existingClientUser->company_id);
        $this->assertSame(User::ROLE_CLIENT_USER, $existingClientUser->role);
    }

    public function test_owner_can_change_roles_only_for_users_in_the_same_client_company(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT, 'Managed Client');
        $otherClient = $this->createCompany(Company::TYPE_CLIENT, 'Other Client');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $clientUser = $this->createUser($client, User::ROLE_CLIENT_USER);
        $otherClientUser = $this->createUser($otherClient, User::ROLE_CLIENT_USER);

        $this->actingAs($owner)
            ->patch(route('platform.client-companies.users.update', [$client, $clientUser]), [
                'role' => User::ROLE_CLIENT_ADMIN,
            ])
            ->assertRedirect();
        $this->assertSame(User::ROLE_CLIENT_ADMIN, $clientUser->fresh()->role);

        $this->patch(route('platform.client-companies.users.update', [$client, $clientUser]), [
            'role' => User::ROLE_CLIENT_USER,
        ])->assertRedirect();
        $this->assertSame(User::ROLE_CLIENT_USER, $clientUser->fresh()->role);

        $this->patch(route('platform.client-companies.users.update', [$client, $otherClientUser]), [
            'role' => User::ROLE_CLIENT_ADMIN,
        ])->assertSessionHasErrors('role');
        $this->assertSame(User::ROLE_CLIENT_USER, $otherClientUser->fresh()->role);

        $this->patch(route('platform.client-companies.users.update', [$client, $clientUser]), [
            'role' => User::ROLE_PLATFORM_OWNER,
        ])->assertSessionHasErrors('role');
        $this->assertSame(User::ROLE_CLIENT_USER, $clientUser->fresh()->role);
    }

    public function test_deactivated_client_falls_back_safely_and_cannot_use_client_admin_portal(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT, 'Client Company');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $clientAdmin = $this->createUser($client, User::ROLE_CLIENT_ADMIN);

        $this->actingAs($owner)
            ->patch(route('platform.client-companies.update', $client), [
                'name' => $client->name,
                'domain' => $client->domain,
                'status' => Company::STATUS_INACTIVE,
            ])
            ->assertRedirect();

        $clientAdmin->refresh()->unsetRelation('company');
        $context = PortalContext::for($clientAdmin);

        $this->assertSame(PortalContext::EXPERIENCE_LEGACY, $context['experience']);
        $this->assertNull($context['company']);
        $this->assertSame('dashboard', $context['landing_route']);
        $this->actingAs($clientAdmin)->get(route('company.dashboard'))->assertForbidden();
        $this->get(route('dashboard'))->assertOk();
    }

    public function test_assigned_client_accounts_receive_the_existing_client_portals(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT, 'Demo Client Ltd');
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $adminCandidate = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);
        $userCandidate = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $this->actingAs($owner)->post(route('platform.client-companies.users.store', $client), [
            'user_id' => $adminCandidate->id,
            'role' => User::ROLE_CLIENT_ADMIN,
        ]);
        $this->post(route('platform.client-companies.users.store', $client), [
            'user_id' => $userCandidate->id,
            'role' => User::ROLE_CLIENT_USER,
        ]);

        $this->actingAs($adminCandidate->fresh())
            ->get(route('company.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Dashboard')
                ->where('auth.portal.experience', PortalContext::EXPERIENCE_CLIENT_ADMIN)
                ->where('auth.portal.company.name', 'Demo Client Ltd'));

        $this->actingAs($userCandidate->fresh())
            ->get(route('dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Dashboard')
                ->where('auth.portal.experience', PortalContext::EXPERIENCE_CLIENT_USER)
                ->where('auth.portal.company.name', 'Demo Client Ltd'));
    }

    public function test_owner_navigation_and_routes_are_owner_only_while_platform_security_still_works(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $staff = $this->createUser($platform, User::ROLE_PLATFORM_STAFF);

        $ownerNavigation = array_column(PortalContext::for($owner)['sidebar_navigation'], 'key');
        $staffNavigation = array_column(PortalContext::for($staff)['sidebar_navigation'], 'key');

        $this->assertContains('client-companies', $ownerNavigation);
        $this->assertNotContains('client-companies', $staffNavigation);
        $this->actingAs($owner)->get(route('dns-security.index'))->assertOk();
        $this->actingAs($staff)->get(route('dns-security.index'))->assertOk();

        foreach ([
            'platform.client-companies.index',
            'platform.client-companies.store',
            'platform.client-companies.show',
            'platform.client-companies.update',
            'platform.client-companies.user-accounts.store',
            'platform.client-companies.users.store',
            'platform.client-companies.users.update',
        ] as $routeName) {
            $middleware = Route::getRoutes()->getByName($routeName)?->gatherMiddleware() ?? [];

            $this->assertContains('platform', $middleware);
            $this->assertContains('platform.owner', $middleware);
        }
    }

    private function createCompany(
        string $type,
        ?string $name = null,
        string $status = Company::STATUS_ACTIVE
    ): Company {
        return Company::create([
            'name' => $name ?? fake()->unique()->company(),
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
