<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use App\Support\PortalContext;
use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class PortalUiSeparationTest extends TestCase
{
    use RefreshDatabase;

    public function test_platform_owner_gets_platform_landing_navigation_and_owner_controls(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM, 'CyberSafe Sdn Bhd');
        $owner = $this->createUser($company, User::ROLE_PLATFORM_OWNER);
        $context = PortalContext::for($owner);

        $this->assertSame('platform.dashboard', PortalContext::landingRouteName($owner));
        $this->assertSame('platform', $context['experience']);
        $this->assertSame('CyberSafe Sdn Bhd', $context['company']['name']);
        $this->assertTrue($context['can_manage_platform_users']);
        $this->assertSame([], $context['navigation']);
        $this->assertSame(
            [
                'security-overview',
                'threat-overview',
                'dns-security',
                'blocked-ips',
                'reports-analytics',
                'whitelist-manager',
                'global-intelligence',
                'tier-3-protection',
                'system-health',
                'audit-trail',
                'email-security',
                'sms-scanner',
                'client-companies',
                'platform-staff',
                'profile',
            ],
            array_column($context['sidebar_navigation'], 'key')
        );

        $this->actingAs($owner)
            ->get(route('platform.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Dashboard')
                ->where('auth.portal.experience', 'platform')
                ->where('auth.portal.title', 'Platform Security Console')
                ->where('auth.portal.company.name', 'CyberSafe Sdn Bhd')
                ->where('auth.portal.can_manage_platform_users', true));

        $this->post('/logout');
        $this->post('/login', [
            'email' => $owner->email,
            'password' => 'password',
        ])->assertRedirect(route('platform.dashboard', absolute: false));
    }

    public function test_platform_staff_gets_platform_landing_without_owner_controls(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM, 'CyberSafe Sdn Bhd');
        $staff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);
        $context = PortalContext::for($staff);

        $this->assertSame('platform.dashboard', PortalContext::landingRouteName($staff));
        $this->assertTrue($context['can_access_platform']);
        $this->assertFalse($context['can_manage_platform_users']);
        $this->assertSame([], $context['navigation']);
        $this->assertSame(
            [
                'security-overview',
                'threat-overview',
                'dns-security',
                'blocked-ips',
                'reports-analytics',
                'whitelist-manager',
                'global-intelligence',
                'tier-3-protection',
                'system-health',
                'audit-trail',
                'email-security',
                'sms-scanner',
                'profile',
            ],
            array_column($context['sidebar_navigation'], 'key')
        );
        $this->assertNotContains('client-companies', array_column($context['sidebar_navigation'], 'key'));
        $this->assertNotContains('platform-staff', array_column($context['sidebar_navigation'], 'key'));

        $this->actingAs($staff)
            ->get(route('platform.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Dashboard')
                ->where('auth.portal.experience', 'platform')
                ->where('auth.portal.can_manage_platform_users', false)
                ->where('auth.is_platform_owner', false));

        $this->post('/logout');
        $this->post('/login', [
            'email' => $staff->email,
            'password' => 'password',
        ])->assertRedirect(route('platform.dashboard', absolute: false));
    }

    public function test_client_admin_gets_company_landing_and_client_only_navigation(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT, 'ABC Technologies');
        $clientAdmin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $context = PortalContext::for($clientAdmin);

        $this->assertSame('company.dashboard', PortalContext::landingRouteName($clientAdmin));
        $this->assertSame('client_admin', $context['experience']);
        $this->assertSame('ABC Technologies', $context['company']['name']);
        $this->assertSame([], $context['sidebar_navigation']);
        $this->assertSame(
            ['dashboard', 'sms.index', 'company.threats.index', 'profile.edit'],
            array_column($context['navigation'], 'route')
        );

        $this->post('/login', [
            'email' => $clientAdmin->email,
            'password' => 'password',
        ])->assertRedirect(route('company.dashboard', absolute: false));

        $this->get(route('company.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Dashboard')
                ->where('auth.portal.experience', 'client_admin')
                ->where('auth.portal.company.name', 'ABC Technologies')
                ->where('auth.portal.can_access_platform', false));
    }

    public function test_client_user_gets_personal_email_landing_without_platform_navigation(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT, 'XYZ Ltd');
        $clientUser = $this->createUser($company, User::ROLE_CLIENT_USER);
        $context = PortalContext::for($clientUser);

        $this->assertSame('dashboard', PortalContext::landingRouteName($clientUser));
        $this->assertSame('client_user', $context['experience']);
        $this->assertSame('My Security', $context['title']);
        $this->assertSame([], $context['sidebar_navigation']);
        $this->assertSame(
            ['dashboard', 'sms.index', 'profile.edit'],
            array_column($context['navigation'], 'route')
        );

        $this->post('/login', [
            'email' => $clientUser->email,
            'password' => 'password',
        ])->assertRedirect(route('dashboard', absolute: false));

        $this->get(route('dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Dashboard')
                ->where('auth.portal.experience', 'client_user')
                ->where('auth.portal.company.name', 'XYZ Ltd')
                ->where('auth.portal.can_access_platform', false));
    }

    public function test_legacy_unassigned_user_gets_unbranded_fallback_navigation(): void
    {
        $legacyUser = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);
        $context = PortalContext::for($legacyUser);

        $this->assertSame('dashboard', PortalContext::landingRouteName($legacyUser));
        $this->assertSame('legacy', $context['experience']);
        $this->assertSame('Personal Security', $context['title']);
        $this->assertNull($context['company']);
        $this->assertSame([], $context['sidebar_navigation']);
        $this->assertSame(
            ['dashboard', 'sms.index', 'profile.edit'],
            array_column($context['navigation'], 'route')
        );

        $this->post('/login', [
            'email' => $legacyUser->email,
            'password' => 'password',
        ])->assertRedirect(route('dashboard', absolute: false));

        $this->get(route('dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Dashboard')
                ->where('auth.portal.experience', 'legacy')
                ->where('auth.portal.company', null)
                ->where('auth.portal.can_access_platform', false));
    }

    public function test_invalid_or_inactive_client_assignments_fall_back_without_company_branding(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $inactiveClientCompany = $this->createCompany(Company::TYPE_CLIENT, 'Inactive Client');
        $inactiveClientCompany->update(['status' => Company::STATUS_INACTIVE]);

        $mismatchedClientAdmin = $this->createUser($platformCompany, User::ROLE_CLIENT_ADMIN);
        $inactiveClientUser = $this->createUser($inactiveClientCompany, User::ROLE_CLIENT_USER);

        foreach ([$mismatchedClientAdmin, $inactiveClientUser] as $user) {
            $context = PortalContext::for($user);

            $this->assertSame('legacy', $context['experience']);
            $this->assertNull($context['company']);
            $this->assertFalse($context['can_access_platform']);
            $this->actingAs($user)->get(route('company.dashboard'))->assertForbidden();
        }
    }

    public function test_client_and_legacy_users_cannot_reach_platform_or_company_admin_routes(): void
    {
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT, 'Client Company');
        $clientAdmin = $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN);
        $clientUser = $this->createUser($clientCompany, User::ROLE_CLIENT_USER);
        $legacyUser = User::factory()->create([
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $this->actingAs($clientAdmin)->get(route('platform.dashboard'))->assertForbidden();
        $this->actingAs($clientUser)->get(route('platform.dashboard'))->assertForbidden();
        $this->actingAs($legacyUser)->get(route('platform.dashboard'))->assertForbidden();
        $this->actingAs($clientUser)->get(route('company.dashboard'))->assertForbidden();
        $this->actingAs($legacyUser)->get(route('company.dashboard'))->assertForbidden();
    }

    public function test_sms_profile_and_email_dashboard_remain_reachable_for_every_experience(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT, 'Client Company');
        $users = [
            $this->createUser($platformCompany, User::ROLE_PLATFORM_OWNER),
            $this->createUser($platformCompany, User::ROLE_PLATFORM_STAFF),
            $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN),
            $this->createUser($clientCompany, User::ROLE_CLIENT_USER),
            User::factory()->create([
                'company_id' => null,
                'role' => User::LEGACY_ROLE_USER,
            ]),
        ];

        foreach ($users as $user) {
            $this->actingAs($user)->get(route('dashboard'))->assertOk();
            $this->actingAs($user)->get(route('sms.index'))->assertOk();
            $this->actingAs($user)->get(route('profile.edit'))->assertOk();
        }
    }

    public function test_already_authenticated_users_are_redirected_to_their_role_landing_without_a_loop(): void
    {
        $platformCompany = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $clientCompany = $this->createCompany(Company::TYPE_CLIENT, 'Client Company');
        $owner = $this->createUser($platformCompany, User::ROLE_PLATFORM_OWNER);
        $clientAdmin = $this->createUser($clientCompany, User::ROLE_CLIENT_ADMIN);

        $this->actingAs($owner)->get(route('login'))
            ->assertRedirect(route('platform.dashboard', absolute: false));

        $this->actingAs($clientAdmin)->get(route('login'))
            ->assertRedirect(route('company.dashboard', absolute: false));
    }

    public function test_platform_email_verification_redirects_to_platform_landing(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $owner = User::factory()->unverified()->create([
            'company_id' => $company->id,
            'role' => User::ROLE_PLATFORM_OWNER,
        ]);

        Event::fake();

        $verificationUrl = URL::temporarySignedRoute(
            'verification.verify',
            now()->addMinutes(60),
            ['id' => $owner->id, 'hash' => sha1($owner->email)]
        );

        $this->actingAs($owner)
            ->get($verificationUrl)
            ->assertRedirect(route('platform.dashboard', ['verified' => 1], false));

        Event::assertDispatched(Verified::class);
        $this->assertTrue($owner->fresh()->hasVerifiedEmail());
    }

    public function test_platform_whitelist_has_a_full_platform_page_wrapper(): void
    {
        $company = $this->createCompany(Company::TYPE_PLATFORM, 'Platform Company');
        $staff = $this->createUser($company, User::ROLE_PLATFORM_STAFF);

        $this->actingAs($staff)
            ->get(route('domains.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Admin/Whitelist')
                ->where('auth.portal.experience', 'platform'));
    }

    private function createCompany(string $type, string $name): Company
    {
        return Company::create([
            'name' => $name,
            'domain' => fake()->unique()->domainName(),
            'type' => $type,
            'status' => Company::STATUS_ACTIVE,
            'is_active' => true,
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
