<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\User;
use App\Models\WhitelistedDomain;
use App\Services\EmailScannerService;
use App\Support\GmailAuthenticationEvidence;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class EmailWhitelistTrustTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config(['services.gemini.mode' => 'mock']);
        Cache::flush();
        Http::preventStrayRequests();
    }

    public function test_spoofed_whitelisted_from_domain_does_not_bypass_scanning(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);

        $result = app(EmailScannerService::class)->scanAndStore(User::factory()->create(), [
            'google_message_id' => 'spoofed-whitelist-before-fix',
            'subject' => 'Review this document',
            'sender' => 'Finance <finance@trusted.example>',
            'snippet' => 'Please review the attached document.',
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertSame('SAFE', $result['record']->verdict);
        $this->assertContains('decision:sender_authentication=unverified_evidence_unavailable', $result['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_normal_policy', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public static function failedAuthenticationCases(): array
    {
        return [
            'DMARC failure' => ['dmarcResult', 'fail', 'decision:sender_authentication=unverified_dmarc_not_pass'],
            'SPF failure' => ['spfResult', 'fail', 'decision:sender_authentication=unverified_spf_not_pass'],
            'DKIM failure' => ['dkimResult', 'fail', 'decision:sender_authentication=unverified_dkim_not_pass'],
            'missing authentication data' => ['dkimResult', null, 'decision:sender_authentication=unverified_dkim_not_pass'],
        ];
    }

    #[DataProvider('failedAuthenticationCases')]
    public function test_failed_or_missing_provider_authentication_rejects_whitelist_trust(
        string $field,
        ?string $value,
        string $decision
    ): void {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);
        $evidence = $this->trustedEvidence([$field => $value]);

        $result = $this->scan(['gmail_authentication' => $evidence]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertContains($decision, $result['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_normal_policy', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public function test_misaligned_provider_identity_rejects_whitelist_trust(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);

        $result = $this->scan([
            'gmail_authentication' => $this->trustedEvidence(['dmarcDomain' => 'attacker.example']),
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertContains('decision:sender_authentication=unverified_dmarc_misaligned', $result['record']->analysis_chain);
        $this->assertContains('decision:whitelist_benefit=rejected_unverified_dmarc_misaligned', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public function test_manual_payload_cannot_supply_attacker_authentication_results(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);
        $user = User::factory()->create();

        $response = $this->actingAs($user)->postJson('/api/scan-email', [
            'emails' => [[
                ...$this->email(),
                'raw_headers' => 'Authentication-Results: attacker.invalid; dmarc=pass header.from=trusted.example',
                'gmail_authentication' => [
                    'dmarcResult' => 'pass',
                    'dmarcDomain' => 'trusted.example',
                    'spfResult' => 'pass',
                    'spfDomain' => 'trusted.example',
                    'dkimResult' => 'pass',
                    'dkimDomain' => 'trusted.example',
                ],
            ]],
        ])->assertOk();

        $response->assertJsonPath('results.0.detection_layer', 'Layer 3 (Mock AI)')
            ->assertJsonPath('results.0.analysis_chain.2', 'decision:sender_authentication=unverified_evidence_unavailable');
        Http::assertNothingSent();
    }

    public function test_clean_aligned_whitelisted_sender_skips_gemini_after_deterministic_layers(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);
        $email = $this->email(['subject' => 'Quarterly update', 'snippet' => 'The quarterly update is available.']);

        $result = $this->scan(array_merge($email, ['gmail_authentication' => $this->trustedEvidence()]));

        $record = $result['record'];
        $this->assertSame('Layer 1 (Verified Whitelist)', $record->detection_layer);
        $this->assertSame('SAFE', $record->verdict);
        $this->assertSame(0, $record->risk_score);
        $this->assertContains('decision:layer_1.whitelist_match=yes', $record->analysis_chain);
        $this->assertContains('decision:sender_authentication=verified_aligned_dmarc_spf_dkim', $record->analysis_chain);
        $this->assertContains('decision:whitelist_benefit=accepted_verified_aligned_dmarc_spf_dkim', $record->analysis_chain);
        $this->assertContains('decision:layer_2.heuristics=ran', $record->analysis_chain);
        $this->assertContains('decision:layer_2_5.virustotal=ran', $record->analysis_chain);
        $this->assertContains('decision:attachment_analysis=skipped_no_pdf', $record->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=skipped_verified_whitelist_clean', $record->analysis_chain);
        $this->assertNotContains($email['subject'], $record->analysis_chain);
        $this->assertNotContains($email['snippet'], $record->analysis_chain);
        Http::assertNothingSent();
    }

    public function test_verified_whitelisted_sender_with_a_suspicious_link_reaches_gemini(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);

        $result = $this->scan([
            'gmail_authentication' => $this->trustedEvidence(),
            'extracted_links' => [[
                'url' => 'https://attacker.example/login',
                'has_suspicious_mismatch' => true,
            ]],
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertContains('decision:whitelist_benefit=overridden_suspicious_link', $result['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_suspicious_link', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public function test_verified_whitelisted_sender_with_suspicious_content_or_attachment_reaches_gemini(): void
    {
        WhitelistedDomain::create(['domain' => 'trusted.example', 'is_active' => true]);

        $contentResult = $this->scan([
            'google_message_id' => 'verified-whitelist-content-signal',
            'gmail_authentication' => $this->trustedEvidence(),
            'snippet' => 'Claim your bitcoin giveaway now.',
        ]);
        $attachmentResult = $this->scan([
            'google_message_id' => 'verified-whitelist-attachment-signal',
            'gmail_authentication' => $this->trustedEvidence(),
            'pdf_attachments' => [[
                'filename' => 'statement.pdf',
                'mime_type' => 'application/pdf',
                'base64_data' => base64_encode('%PDF-1.4 synthetic'),
            ]],
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $contentResult['record']->detection_layer);
        $this->assertContains('decision:whitelist_benefit=overridden_heuristic_signal', $contentResult['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_heuristic_signal', $contentResult['record']->analysis_chain);
        $this->assertSame('Layer 3 (Mock AI)', $attachmentResult['record']->detection_layer);
        $this->assertContains('decision:attachment_analysis=ran', $attachmentResult['record']->analysis_chain);
        $this->assertContains('decision:whitelist_benefit=overridden_attachment_present', $attachmentResult['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_attachment_present', $attachmentResult['record']->analysis_chain);
        Http::assertNothingSent();
    }

    public static function domainMatchingCases(): array
    {
        return [
            'exact match normalizes case and trailing dots' => ['Person <person@TRUSTED.EXAMPLE.>', 'trusted.example', true],
            'permitted subdomain matches dot boundary' => ['Person <person@billing.trusted.example>', 'billing.trusted.example', true],
            'suffix lookalike does not match' => ['Person <person@trusted.example.attacker.test>', 'trusted.example.attacker.test', false],
            'malformed sender does not match' => ['Person <person@trusted..example>', 'trusted.example', false],
        ];
    }

    #[DataProvider('domainMatchingCases')]
    public function test_domain_matching_is_normalized_and_suffix_safe(string $sender, string $authenticatedDomain, bool $accepted): void
    {
        WhitelistedDomain::create(['domain' => 'Trusted.Example.', 'is_active' => true]);

        $result = $this->scan([
            'google_message_id' => 'domain-policy-'.sha1($sender),
            'sender' => $sender,
            'gmail_authentication' => $this->trustedEvidence([
                'dmarcDomain' => $authenticatedDomain,
                'spfDomain' => $authenticatedDomain,
                'dkimDomain' => $authenticatedDomain,
            ]),
        ]);

        $this->assertSame($accepted ? 'Layer 1 (Verified Whitelist)' : 'Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertContains(
            $accepted ? 'decision:layer_3.gemini=skipped_verified_whitelist_clean' : 'decision:layer_3.gemini=called_normal_policy',
            $result['record']->analysis_chain
        );
        Http::assertNothingSent();
    }

    public function test_non_whitelisted_email_keeps_its_existing_mock_analysis_path(): void
    {
        $result = $this->scan([
            'sender' => 'Person <person@untrusted.example>',
            'gmail_authentication' => $this->trustedEvidence([
                'dmarcDomain' => 'untrusted.example',
                'spfDomain' => 'untrusted.example',
                'dkimDomain' => 'untrusted.example',
            ]),
        ]);

        $this->assertSame('Layer 3 (Mock AI)', $result['record']->detection_layer);
        $this->assertSame('SAFE', $result['record']->verdict);
        $this->assertSame(10, $result['record']->risk_score);
        $this->assertContains('decision:layer_1.whitelist_match=no', $result['record']->analysis_chain);
        $this->assertContains('decision:layer_3.gemini=called_normal_policy', $result['record']->analysis_chain);
        Http::assertNothingSent();
    }

    private function scan(array $overrides = []): array
    {
        return app(EmailScannerService::class)->scanAndStore(
            User::factory()->create(),
            array_merge($this->email(), $overrides)
        );
    }

    private function email(array $overrides = []): array
    {
        return array_merge([
            'google_message_id' => 'whitelist-trust-'.fake()->uuid(),
            'subject' => 'Routine account update',
            'sender' => 'Finance <finance@trusted.example>',
            'snippet' => 'A routine account update is available.',
            'body' => 'A routine account update is available.',
        ], $overrides);
    }

    private function trustedEvidence(array $overrides = []): GmailAuthenticationEvidence
    {
        $attributes = array_merge([
            'dmarcResult' => 'pass',
            'dmarcDomain' => 'trusted.example',
            'spfResult' => 'pass',
            'spfDomain' => 'trusted.example',
            'dkimResult' => 'pass',
            'dkimDomain' => 'trusted.example',
        ], $overrides);

        return new GmailAuthenticationEvidence(...$attributes);
    }
}
