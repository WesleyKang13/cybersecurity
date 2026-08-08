<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Jobs\ScanGmailJob;
use App\Models\ScannedEmail;
use App\Models\User;
use App\Services\EmailOriginService;
use App\Services\EmailScannerService;
use App\Services\LinkExtractionService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Mockery;
use Tests\TestCase;

class ScanGmailJobTest extends TestCase
{
    use RefreshDatabase;

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
