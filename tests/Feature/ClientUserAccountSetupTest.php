<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\User;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Tests\TestCase;

class ClientUserAccountSetupTest extends TestCase
{
    use RefreshDatabase;

    public function test_owner_can_create_both_client_roles_for_the_route_company(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $otherClient = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        foreach ([User::ROLE_CLIENT_ADMIN, User::ROLE_CLIENT_USER] as $index => $role) {
            $email = "new-client-user-{$index}@example.test";

            $this->actingAs($owner)
                ->post(route('platform.client-companies.user-accounts.store', $client), [
                    'name' => "New Client User {$index}",
                    'email' => $email,
                    'account_role' => $role,
                    'company_id' => $otherClient->id,
                    'role' => User::ROLE_PLATFORM_OWNER,
                ])
                ->assertRedirect()
                ->assertSessionHas('account_setup_url');

            $user = User::query()->where('email', $email)->firstOrFail();

            $this->assertSame($client->id, $user->company_id);
            $this->assertSame($role, $user->role);
            $this->assertFalse(Hash::check('password', $user->password));
            $this->assertFalse(Hash::check('Password123', $user->password));
            $this->assertFalse(Hash::check('123456', $user->password));
            Notification::assertSentTo($user, ResetPassword::class);
        }
    }

    public function test_existing_eligible_email_is_assigned_without_creating_a_duplicate(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $candidate = User::factory()->create([
            'name' => 'Existing Name',
            'email' => 'transition@example.test',
            'company_id' => null,
            'role' => User::LEGACY_ROLE_USER,
        ]);

        $this->actingAs($owner)
            ->post(route('platform.client-companies.user-accounts.store', $client), [
                'name' => 'Replacement Name Is Ignored',
                'email' => 'TRANSITION@EXAMPLE.TEST',
                'account_role' => User::ROLE_CLIENT_ADMIN,
            ])
            ->assertRedirect()
            ->assertSessionHasNoErrors();

        $candidate->refresh();
        $this->assertSame('Existing Name', $candidate->name);
        $this->assertSame($client->id, $candidate->company_id);
        $this->assertSame(User::ROLE_CLIENT_ADMIN, $candidate->role);
        $this->assertSame(1, User::query()->whereRaw('LOWER(email) = ?', ['transition@example.test'])->count());
        Notification::assertNothingSent();
    }

    public function test_same_company_other_company_and_platform_emails_are_rejected_safely(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $otherClient = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);
        $sameCompanyUser = $this->createUser($client, User::ROLE_CLIENT_USER);
        $otherCompanyUser = $this->createUser($otherClient, User::ROLE_CLIENT_USER);
        $platformStaff = $this->createUser($platform, User::ROLE_PLATFORM_STAFF);

        foreach ([$sameCompanyUser, $otherCompanyUser, $platformStaff] as $existingUser) {
            $this->actingAs($owner)
                ->post(route('platform.client-companies.user-accounts.store', $client), [
                    'name' => 'Duplicate Attempt',
                    'email' => $existingUser->email,
                    'account_role' => User::ROLE_CLIENT_ADMIN,
                ])
                ->assertSessionHasErrors('email');
        }

        $this->assertSame($client->id, $sameCompanyUser->fresh()->company_id);
        $this->assertSame($otherClient->id, $otherCompanyUser->fresh()->company_id);
        $this->assertSame($platform->id, $platformStaff->fresh()->company_id);
        Notification::assertNothingSent();
    }

    public function test_platform_roles_and_platform_company_route_are_rejected(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        foreach ([User::ROLE_PLATFORM_OWNER, User::ROLE_PLATFORM_STAFF] as $role) {
            $this->actingAs($owner)
                ->post(route('platform.client-companies.user-accounts.store', $client), [
                    'name' => 'Invalid Role',
                    'email' => str_replace('_', '-', $role).'@example.test',
                    'account_role' => $role,
                ])
                ->assertSessionHasErrors('account_role');
        }

        $this->post(route('platform.client-companies.user-accounts.store', $platform), [
            'name' => 'Invalid Tenant',
            'email' => 'invalid-tenant@example.test',
            'account_role' => User::ROLE_CLIENT_USER,
        ])->assertNotFound();

        $this->assertDatabaseMissing('users', ['email' => 'invalid-tenant@example.test']);
        Notification::assertNothingSent();
    }

    public function test_only_an_active_platform_owner_can_create_client_accounts(): void
    {
        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $inactivePlatform = $this->createCompany(Company::TYPE_PLATFORM, Company::STATUS_INACTIVE);
        $deniedUsers = [
            $this->createUser($platform, User::ROLE_PLATFORM_STAFF),
            $this->createUser($client, User::ROLE_CLIENT_ADMIN),
            $this->createUser($client, User::ROLE_CLIENT_USER),
            $this->createUser($inactivePlatform, User::ROLE_PLATFORM_OWNER),
            User::factory()->create(['company_id' => null, 'role' => User::LEGACY_ROLE_USER]),
        ];

        foreach ($deniedUsers as $index => $user) {
            $this->actingAs($user)
                ->post(route('platform.client-companies.user-accounts.store', $client), [
                    'name' => 'Unauthorized User',
                    'email' => "unauthorized-{$index}@example.test",
                    'account_role' => User::ROLE_CLIENT_USER,
                ])
                ->assertForbidden();
        }

        $this->assertDatabaseMissing('users', ['name' => 'Unauthorized User']);
    }

    public function test_account_setup_token_is_hashed_single_use_and_allows_authentication(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)
            ->post(route('platform.client-companies.user-accounts.store', $client), [
                'name' => 'Setup User',
                'email' => 'setup-user@example.test',
                'account_role' => User::ROLE_CLIENT_ADMIN,
            ])
            ->assertSessionHas('account_setup_url');

        $user = User::query()->where('email', 'setup-user@example.test')->firstOrFail();
        $token = $this->setupTokenFor($user);
        $storedToken = DB::table('password_reset_tokens')->where('email', $user->email)->value('token');

        $this->assertNotSame($token, $storedToken);
        $this->assertTrue(Password::broker()->tokenExists($user, $token));

        $this->post('/logout');

        $this->post(route('password.store'), [
            'token' => $token,
            'email' => $user->email,
            'password' => 'SecurePassword!234',
            'password_confirmation' => 'SecurePassword!234',
        ])->assertRedirect(route('login'));

        $this->assertTrue(Hash::check('SecurePassword!234', $user->fresh()->password));
        $this->assertFalse(Password::broker()->tokenExists($user, $token));

        $this->post(route('password.store'), [
            'token' => $token,
            'email' => $user->email,
            'password' => 'AnotherSecurePassword!234',
            'password_confirmation' => 'AnotherSecurePassword!234',
        ])->assertSessionHasErrors('email');

        $this->post(route('login'), [
            'email' => $user->email,
            'password' => 'SecurePassword!234',
        ])->assertRedirect(route('company.dashboard', absolute: false));
    }

    public function test_expired_account_setup_token_is_rejected(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $client = $this->createCompany(Company::TYPE_CLIENT);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)->post(route('platform.client-companies.user-accounts.store', $client), [
            'name' => 'Expiring User',
            'email' => 'expiring-user@example.test',
            'account_role' => User::ROLE_CLIENT_USER,
        ]);

        $user = User::query()->where('email', 'expiring-user@example.test')->firstOrFail();
        $token = $this->setupTokenFor($user);

        $this->post('/logout');
        $this->travel(61)->minutes();

        $this->post(route('password.store'), [
            'token' => $token,
            'email' => $user->email,
            'password' => 'SecurePassword!234',
            'password_confirmation' => 'SecurePassword!234',
        ])->assertSessionHasErrors('email');

        $this->assertFalse(Hash::check('SecurePassword!234', $user->fresh()->password));
    }

    public function test_platform_staff_creation_also_uses_secure_account_setup(): void
    {
        Notification::fake();

        $platform = $this->createCompany(Company::TYPE_PLATFORM);
        $owner = $this->createUser($platform, User::ROLE_PLATFORM_OWNER);

        $this->actingAs($owner)->post(route('admin.users.store'), [
            'name' => 'New Platform Staff',
            'email' => 'new-platform-staff@example.test',
        ])->assertSessionHas('account_setup_url');

        $staff = User::query()->where('email', 'new-platform-staff@example.test')->firstOrFail();

        $this->assertSame($platform->id, $staff->company_id);
        $this->assertSame(User::ROLE_PLATFORM_STAFF, $staff->role);
        $this->assertFalse(Hash::check('password', $staff->password));
        Notification::assertSentTo($staff, ResetPassword::class);
    }

    private function setupTokenFor(User $user): string
    {
        $token = null;

        Notification::assertSentTo(
            $user,
            ResetPassword::class,
            function (ResetPassword $notification) use (&$token): bool {
                $token = $notification->token;

                return true;
            }
        );

        $this->assertIsString($token);

        return $token;
    }

    private function createCompany(
        string $type,
        string $status = Company::STATUS_ACTIVE
    ): Company {
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
