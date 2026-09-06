<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Jobs\ScanGmailJob;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Models\WhitelistedDomain;
use App\Services\EmailOriginService;
use App\Services\EmailScannerService;
use App\Services\LinkExtractionService;
use App\Support\GmailAuthenticationEvidence;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Mockery;
use Tests\TestCase;

class ScanGmailJobTest extends TestCase
{
    use RefreshDatabase;

    public function test_gmail_job_passes_provider_authentication_to_the_real_whitelist_policy(): void
    {
        config(['services.gemini.mode' => 'mock']);
        Cache::flush();
        Http::preventStrayRequests();
        Http::fake();
        Mail::fake();
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);
        $user = User::factory()->create([
            'google_access_token' => 'synthetic-access-token',
            'auto_quarantine' => false,
        ]);
        $gmail = Mockery::mock('overload:App\Services\GmailService');
        $gmail->shouldReceive('fetchLatestEmails')->once()->with(5)->andReturn([[
            'id' => 'authenticated-whitelist-gmail-message',
            'subject' => 'Quarterly update',
            'from' => 'Finance <finance@trusted.example>',
            'snippet' => 'The quarterly update is available.',
            'body' => 'The quarterly update is available.',
            'gmail_authentication' => new GmailAuthenticationEvidence(
                dmarcResult: 'pass',
                dmarcDomain: 'trusted.example',
                spfResult: 'pass',
                spfDomain: 'trusted.example',
                dkimResult: 'pass',
                dkimDomain: 'trusted.example',
            ),
        ]]);
        $origin = Mockery::mock(EmailOriginService::class);
        $origin->shouldNotReceive('trace');
        $links = Mockery::mock(LinkExtractionService::class);
        $links->shouldReceive('extractAndInspect')->once()->andReturn([]);

        (new ScanGmailJob($user))->handle(app(EmailScannerService::class), $origin, $links);

        $record = ScannedEmail::where('user_id', $user->id)->sole();
        $this->assertSame('Layer 1 (Verified Whitelist)', $record->detection_layer);
        $this->assertContains('decision:sender_authentication=verified_aligned_dmarc_spf_dkim', $record->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=skipped_verified_whitelist_clean', $record->analysis_chain);
        Http::assertNothingSent();
        Mail::assertNothingSent();
    }

    public function test_real_scanner_isolates_gmail_owners_and_deduplicates_job_retries(): void
    {
        config(['services.gemini.mode' => 'mock']);
        Cache::flush();
        Http::preventStrayRequests();
        Http::fake();
        Mail::fake();

        $userA = User::factory()->create();
        $userB = User::factory()->create([
            'google_access_token' => 'synthetic-access-token',
            'auto_quarantine' => false,
        ]);
        $scanner = app(EmailScannerService::class);
        $original = $scanner->scanAndStore($userA, [
            'google_message_id' => 'synthetic-gmail-shared-message',
            'subject' => 'Private subject A',
            'sender' => 'private@synthetic-a.xyz',
            'snippet' => 'Private snippet A',
        ])['record'];
        $original->delete();
        $originalAttributes = $original->fresh()->getRawOriginal();

        $gmail = Mockery::mock('overload:App\Services\GmailService');
        $gmail->shouldReceive('fetchLatestEmails')->once()->with(5)->andReturn([[
            'id' => $original->google_message_id,
            'subject' => 'Gmail subject B',
            'from' => 'sender@synthetic-b.example',
            'snippet' => 'Gmail snippet B',
            'body' => 'Synthetic Gmail body B',
        ]]);
        $origin = Mockery::mock(EmailOriginService::class);
        $origin->shouldNotReceive('trace');
        $links = Mockery::mock(LinkExtractionService::class);
        $links->shouldReceive('extractAndInspect')->twice()->andReturn([]);

        (new ScanGmailJob($userB))->handle($scanner, $origin, $links);

        $owned = ScannedEmail::where('user_id', $userB->id)->sole();
        $this->assertSame('Gmail subject B', $owned->subject);
        $this->assertSame('sender@synthetic-b.example', $owned->sender);
        $this->assertSame('Gmail snippet B', $owned->snippet);
        $this->assertSame('SAFE', $owned->verdict);
        $attributes = $owned->getRawOriginal();
        Cache::shouldReceive('remember')->never();

        (new ScanGmailJob($userB))->handle($scanner, $origin, $links);

        $this->assertSame($attributes, $owned->fresh()->getRawOriginal());
        $this->assertSame($originalAttributes, $original->fresh()->getRawOriginal());
        $this->assertDatabaseCount('scanned_emails', 2);
        Http::assertNothingSent();
        Mail::assertNothingSent();
    }

    public function test_it_attaches_origin_trace_to_new_high_risk_scans(): void
    {
        Http::fake();
        Mail::fake();

        $user = User::factory()->create([
            'google_access_token' => 'access-token',
            'google_refresh_token' => 'refresh-token',
            'auto_quarantine' => false,
        ]);

        $scannedEmail = ScannedEmail::create([
            'user_id' => $user->id,
            'google_message_id' => 'gmail-message-1',
            'subject' => 'Urgent wire request',
            'sender' => 'ceo@example.com',
            'snippet' => 'Please process immediately.',
            'is_threat' => true,
            'detection_layer' => 'Layer 3 (AI Analysis)',
            'severity' => 'high',
            'reason' => 'High-risk BEC indicators detected.',
            'risk_score' => 95,
            'verdict' => 'MALICIOUS',
            'threat_category' => 'BEC/Invoice Fraud',
            'analysis_chain' => [
                'Step 1: Evaluate sender identity and domain.',
                'Step 2: Evaluate financial or psychological intent.',
                'Step 3: Contextualize VirusTotal metadata.',
            ],
            'final_reasoning' => 'High-risk BEC indicators detected.',
        ]);

        $gmailMock = Mockery::mock('overload:App\Services\GmailService');
        $gmailMock->shouldReceive('fetchLatestEmails')->once()->with(5)->andReturn([
            [
                'id' => 'gmail-message-1',
                'subject' => 'Urgent wire request',
                'from' => 'ceo@example.com',
                'snippet' => 'Please process immediately.',
                'body' => 'Please process immediately.',
                'html_body' => '<p>Please process immediately.</p>',
                'pdf_attachments' => [],
                'raw_headers' => "Received: from attacker.example (attacker.example [203.0.113.10])\r\nAuthentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail",
            ],
        ]);

        $scanner = Mockery::mock(EmailScannerService::class);
        $scanner->shouldReceive('scanAndStore')->once()->andReturn([
            'record' => $scannedEmail,
            'created' => true,
        ]);

        $originService = Mockery::mock(EmailOriginService::class);
        $originService->shouldReceive('trace')->once()->andReturn([
            'originating_ip' => '203.0.113.10',
            'location' => ['country' => 'Testland', 'city' => 'Test City'],
            'isp' => ['name' => 'Test ISP', 'asn' => 'AS64500', 'organization' => 'Test Org'],
            'provider_name' => null,
            'is_trusted_provider' => false,
            'origin_note' => null,
            'authentication' => ['spf_pass' => false, 'dkim_pass' => false, 'domain_alignment_pass' => false],
            'is_hosting_provider' => false,
            'is_hosting_provider_warning' => false,
            'is_proxy_or_vpn' => false,
            'hop_count' => 1,
            'hops_detail' => [
                [
                    'sequence' => 1,
                    'source_header' => 'Received',
                    'ip' => '203.0.113.10',
                    'raw_header' => 'Received: from attacker.example (attacker.example [203.0.113.10])',
                ],
            ],
        ]);

        $linkExtractionService = Mockery::mock(LinkExtractionService::class);
        $linkExtractionService->shouldReceive('extractAndInspect')->once()->andReturn([]);

        (new ScanGmailJob($user))->handle($scanner, $originService, $linkExtractionService);

        $this->assertSame('203.0.113.10', $scannedEmail->fresh()->origin_trace['originating_ip']);
        Mail::assertNothingSent();
    }
}
