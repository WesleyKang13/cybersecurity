<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\GmailAuthenticationEvidence;
use Google\Service\Gmail\MessagePartHeader;
use Tests\TestCase;

class GmailAuthenticationEvidenceTest extends TestCase
{
    public function test_it_extracts_only_the_first_gmail_authentication_results_header(): void
    {
        $evidence = GmailAuthenticationEvidence::fromGmailHeaders([
            $this->header('Authentication-Results', 'mx.google.com; dmarc=pass header.from=trusted.example; spf=pass smtp.mailfrom=mailer@trusted.example; dkim=pass header.i=signer@trusted.example'),
            // A sender can forge this value, but Gmail's own result is first.
            $this->header('Authentication-Results', 'mx.google.com; dmarc=fail header.from=attacker.example; spf=fail smtp.mailfrom=attacker.example; dkim=fail header.i=@attacker.example'),
        ]);

        $this->assertInstanceOf(GmailAuthenticationEvidence::class, $evidence);
        $this->assertSame('pass', $evidence->dmarcResult);
        $this->assertSame('trusted.example', $evidence->dmarcDomain);
        $this->assertSame('pass', $evidence->spfResult);
        $this->assertSame('trusted.example', $evidence->spfDomain);
        $this->assertSame('pass', $evidence->dkimResult);
        $this->assertSame('trusted.example', $evidence->dkimDomain);
    }

    public function test_attacker_authentication_results_header_is_not_trusted(): void
    {
        $evidence = GmailAuthenticationEvidence::fromGmailHeaders([
            $this->header('Authentication-Results', 'attacker.invalid; dmarc=pass header.from=trusted.example; spf=pass smtp.mailfrom=trusted.example; dkim=pass header.i=@trusted.example'),
            $this->header('Authentication-Results', 'mx.google.com; dmarc=pass header.from=trusted.example; spf=pass smtp.mailfrom=trusted.example; dkim=pass header.i=@trusted.example'),
        ]);

        $this->assertNull($evidence);
    }

    public function test_conflicting_or_incomplete_gmail_results_fail_closed(): void
    {
        $evidence = GmailAuthenticationEvidence::fromGmailHeaders([
            $this->header('Authentication-Results', 'mx.google.com; dmarc=pass dmarc=fail header.from=trusted.example; spf=pass smtp.mailfrom=trusted.example; dkim=pass header.i=@trusted.example'),
        ]);

        $this->assertInstanceOf(GmailAuthenticationEvidence::class, $evidence);
        $this->assertNull($evidence->dmarcResult);
    }

    private function header(string $name, string $value): MessagePartHeader
    {
        return new MessagePartHeader(['name' => $name, 'value' => $value]);
    }
}
