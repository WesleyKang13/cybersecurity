<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\Company;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Support\PortalContext;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ClientCompanyThreatReviewTest extends TestCase
{
    use RefreshDatabase;

    public function test_only_an_active_client_admin_can_access_company_threat_review(): void
    {
        $activeClient = $this->createCompany(Company::TYPE_CLIENT, Company::STATUS_ACTIVE);
        $inactiveClient = $this->createCompany(Company::TYPE_CLIENT, Company::STATUS_INACTIVE);
        $platform = $this->createCompany(Company::TYPE_PLATFORM, Company::STATUS_ACTIVE);
        $clientAdmin = $this->createUser($activeClient, User::ROLE_CLIENT_ADMIN);
        $deniedUsers = [
            $this->createUser($activeClient, User::ROLE_CLIENT_USER),
            $this->createUser($inactiveClient, User::ROLE_CLIENT_ADMIN),
            $this->createUser($platform, User::ROLE_CLIENT_ADMIN),
            $this->createUser($platform, User::ROLE_PLATFORM_OWNER),
            $this->createUser($platform, User::ROLE_PLATFORM_STAFF),
            User::factory()->create([
                'company_id' => null,
                'role' => User::ROLE_CLIENT_ADMIN,
            ]),
            User::factory()->create([
                'company_id' => null,
                'role' => User::LEGACY_ROLE_USER,
            ]),
        ];

        $this->actingAs($clientAdmin)
            ->get(route('company.threats.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Threats/Index')
                ->where('auth.portal.experience', PortalContext::EXPERIENCE_CLIENT_ADMIN));

        foreach ($deniedUsers as $user) {
            $this->actingAs($user)
                ->get(route('company.threats.index'))
                ->assertForbidden();
        }
    }

    public function test_review_queue_contains_only_high_and_critical_threats_from_the_admin_company(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $otherCompany = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $employee = $this->createUser($company, User::ROLE_CLIENT_USER);
        $otherEmployee = $this->createUser($otherCompany, User::ROLE_CLIENT_USER);
        $high = $this->createEmail($employee, 'high', true, ['risk_score' => 82]);
        $critical = $this->createEmail($employee, 'CRITICAL', true, ['risk_score' => 98]);
        $this->createEmail($employee, 'medium', true, ['risk_score' => 65]);
        $this->createEmail($employee, 'low', true, ['risk_score' => 20]);
        $this->createEmail($employee, 'clean', false);
        $this->createEmail($otherEmployee, 'critical', true, ['risk_score' => 99]);

        $this->actingAs($admin)
            ->get(route('company.threats.index', [
                'company_id' => $otherCompany->id,
            ]))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Threats/Index')
                ->has('threats.data', 2)
                ->where('threats.data.0.id', $critical->id)
                ->where('threats.data.0.severity', 'critical')
                ->where('threats.data.1.id', $high->id)
                ->where('filters.risk', 'all')
                ->where('filters.review', 'all')
                ->where('summary.critical', 1)
                ->where('summary.high', 1)
                ->where('summary.unreviewed', 2)
                ->where('summary.quarantined', 0));
    }

    public function test_unreviewed_threats_are_ordered_before_reviewed_threats(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $employee = $this->createUser($company, User::ROLE_CLIENT_USER);
        $reviewedCritical = $this->createEmail($employee, 'critical', true, [
            'admin_reviewed_at' => now()->subMinute(),
            'admin_reviewed_by_user_id' => $admin->id,
        ]);
        $unreviewedHigh = $this->createEmail($employee, 'high', true);

        $this->actingAs($admin)
            ->get(route('company.threats.index'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->where('threats.data.0.id', $unreviewedHigh->id)
                ->where('threats.data.0.reviewed_at', null)
                ->where('threats.data.1.id', $reviewedCritical->id));
    }

    public function test_filters_and_company_dashboard_summary_use_the_same_scoped_review_queue(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $otherCompany = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $employee = $this->createUser($company, User::ROLE_CLIENT_USER);
        $otherEmployee = $this->createUser($otherCompany, User::ROLE_CLIENT_USER);
        $reviewed = $this->createEmail($employee, 'high', true, [
            'admin_reviewed_at' => now()->subHour(),
            'admin_reviewed_by_user_id' => $admin->id,
        ]);
        $this->createEmail($employee, 'critical', true, ['is_quarantined' => true]);
        $this->createEmail($employee, 'medium', true);
        $this->createEmail($otherEmployee, 'critical', true, ['is_quarantined' => true]);

        $this->actingAs($admin)
            ->get(route('company.threats.index', [
                'risk' => 'high',
                'review' => 'reviewed',
            ]))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->has('threats.data', 1)
                ->where('threats.data.0.id', $reviewed->id)
                ->where('filters.risk', 'high')
                ->where('filters.review', 'reviewed'));

        $this->get(route('company.dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Dashboard')
                ->where('threatSummary.high_critical', 2)
                ->where('threatSummary.critical', 1)
                ->where('threatSummary.high', 1)
                ->where('threatSummary.unreviewed', 1)
                ->where('threatSummary.quarantined', 1)
                ->where('threatSummary.recent', 2));
    }

    public function test_detail_is_company_scoped_and_exposes_metadata_without_mailbox_content(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $otherCompany = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $employee = $this->createUser($company, User::ROLE_CLIENT_USER);
        $employee->update([
            'google_access_token' => 'sensitive-access-token',
            'google_refresh_token' => 'sensitive-refresh-token',
            'token' => ['access_token' => 'legacy-sensitive-token'],
        ]);
        $otherEmployee = $this->createUser($otherCompany, User::ROLE_CLIENT_USER);
        $threat = $this->createEmail($employee, 'high', true, [
            'snippet' => 'Private employee message content',
            'analysis_chain' => ['Internal scanner trace'],
            'origin_trace' => [
                'originating_ip' => '203.0.113.10',
                'location' => ['country' => 'Testland', 'city' => 'Test City'],
                'isp' => ['organization' => 'Example Host'],
                'authentication' => ['spf_pass' => false, 'dkim_pass' => true, 'domain_alignment_pass' => false],
                'hops_detail' => [['raw_header' => 'Sensitive raw header']],
            ],
        ]);
        $otherThreat = $this->createEmail($otherEmployee, 'critical', true);
        $lowEmail = $this->createEmail($employee, 'low', true);

        $this->actingAs($admin)
            ->get(route('company.threats.show', $threat))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Client/Threats/Show')
                ->where('threat.id', $threat->id)
                ->where('threat.employee.email', $employee->email)
                ->where('threat.origin.originating_ip', '203.0.113.10')
                ->missing('threat.snippet')
                ->missing('threat.google_message_id')
                ->missing('threat.analysis_chain')
                ->missing('threat.body')
                ->missing('threat.attachments')
                ->missing('threat.employee.google_access_token')
                ->missing('threat.employee.google_refresh_token')
                ->missing('threat.employee.token')
                ->missing('threat.origin.hops_detail'));

        $this->get(route('company.threats.show', $otherThreat))->assertNotFound();
        $this->get(route('company.threats.show', $lowEmail))->assertNotFound();
    }

    public function test_client_admin_can_mark_an_own_company_threat_reviewed_without_changing_detection_state(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $employee = $this->createUser($company, User::ROLE_CLIENT_USER);
        $threat = $this->createEmail($employee, 'high', true, [
            'risk_score' => 91,
            'verdict' => 'MALICIOUS',
            'is_quarantined' => true,
        ]);

        $this->actingAs($admin)
            ->patch(route('company.threats.review', $threat))
            ->assertRedirect();

        $threat->refresh();
        $this->assertNotNull($threat->admin_reviewed_at);
        $this->assertSame($admin->id, $threat->admin_reviewed_by_user_id);
        $this->assertSame('high', $threat->severity);
        $this->assertSame(91, $threat->risk_score);
        $this->assertSame('MALICIOUS', $threat->verdict);
        $this->assertTrue($threat->is_quarantined);
        $this->assertTrue($threat->is_threat);

        $firstReviewedAt = $threat->admin_reviewed_at->copy();
        $secondAdmin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);

        $this->actingAs($secondAdmin)
            ->patch(route('company.threats.review', $threat))
            ->assertRedirect();

        $threat->refresh();
        $this->assertTrue($threat->admin_reviewed_at->equalTo($firstReviewedAt));
        $this->assertSame($admin->id, $threat->admin_reviewed_by_user_id);
    }

    public function test_review_write_cannot_cross_tenants_or_be_used_by_client_users(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $otherCompany = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $clientUser = $this->createUser($company, User::ROLE_CLIENT_USER);
        $otherEmployee = $this->createUser($otherCompany, User::ROLE_CLIENT_USER);
        $otherThreat = $this->createEmail($otherEmployee, 'critical', true);

        $this->actingAs($admin)
            ->patch(route('company.threats.review', $otherThreat))
            ->assertNotFound();

        $this->actingAs($clientUser)
            ->patch(route('company.threats.review', $otherThreat))
            ->assertForbidden();

        $this->assertNull($otherThreat->fresh()->admin_reviewed_at);
        $this->assertNull($otherThreat->fresh()->admin_reviewed_by_user_id);
    }

    public function test_client_navigation_and_personal_email_isolation_remain_intact(): void
    {
        $company = $this->createCompany(Company::TYPE_CLIENT);
        $admin = $this->createUser($company, User::ROLE_CLIENT_ADMIN);
        $clientUser = $this->createUser($company, User::ROLE_CLIENT_USER);
        $adminEmail = $this->createEmail($admin, 'high', true);
        $this->createEmail($clientUser, 'critical', true);
        $adminNavigation = array_column(PortalContext::for($admin)['navigation'], 'key');
        $userNavigation = array_column(PortalContext::for($clientUser)['navigation'], 'key');

        $this->assertContains('company-threat-review', $adminNavigation);
        $this->assertNotContains('company-threat-review', $userNavigation);

        $this->actingAs($clientUser)
            ->get(route('dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Dashboard')
                ->has('recentAlerts', 1)
                ->where('recentAlerts.0.id', 'email_'.$clientUser->scannedEmails()->firstOrFail()->id));

        $this->actingAs($admin)
            ->get(route('dashboard'))
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->has('recentAlerts', 1)
                ->where('recentAlerts.0.id', 'email_'.$adminEmail->id));
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

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function createEmail(User $user, string $severity, bool $isThreat, array $attributes = []): ScannedEmail
    {
        $email = ScannedEmail::create([
            'user_id' => $user->id,
            'google_message_id' => fake()->unique()->uuid(),
            'subject' => 'Payment required',
            'sender' => 'invoice@example.test',
            'snippet' => 'Private message preview',
            'is_threat' => $isThreat,
            'severity' => $severity,
            'reason' => 'Security indicators require review.',
            'risk_score' => 80,
            'is_quarantined' => false,
            'verdict' => $isThreat ? 'MALICIOUS' : 'SAFE',
            'threat_category' => $isThreat ? 'Phishing' : 'None',
            'final_reasoning' => 'Security indicators require review.',
            ...array_diff_key($attributes, array_flip([
                'admin_reviewed_at',
                'admin_reviewed_by_user_id',
            ])),
        ]);

        if (array_key_exists('admin_reviewed_at', $attributes)) {
            $email->forceFill([
                'admin_reviewed_at' => $attributes['admin_reviewed_at'],
                'admin_reviewed_by_user_id' => $attributes['admin_reviewed_by_user_id'] ?? null,
            ])->save();
        }

        return $email;
    }
}
