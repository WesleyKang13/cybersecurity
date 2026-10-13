<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Services\ThreatClassificationService;
use App\Support\ThreatEventPresentation;
use PHPUnit\Framework\TestCase;

class ThreatClassificationServiceTest extends TestCase
{
    public function test_recognizable_probe_paths_are_classified_without_claiming_compromise(): void
    {
        $classifier = new ThreatClassificationService;

        $this->assertSame([
            'event_type' => 'environment_file_probe',
            'severity' => 'high',
            'reason' => 'Attempted request for a sensitive environment configuration path.',
        ], $classifier->classifyFromPath('/.env'));
        $this->assertSame('wordpress_admin_probe', $classifier->classifyFromPath('/wp-login.php')['event_type']);
        $this->assertNull($classifier->classifyFromPath('/account/profile'));
    }

    public function test_cloudflare_and_outcome_labels_preserve_raw_data_semantics(): void
    {
        $this->assertSame('Cloudflare WAF Managed Rules', ThreatEventPresentation::sourceLabel('firewallManaged'));
        $this->assertSame('Cloudflare IP Access Rules', ThreatEventPresentation::sourceLabel('accessRules'));
        $this->assertSame('Tier 3 Application Middleware', ThreatEventPresentation::sourceLabel('app_middleware'));
        $this->assertSame('Blocked', ThreatEventPresentation::actionLabel('block'));
        $this->assertSame('Challenged', ThreatEventPresentation::actionLabel('managed_challenge'));
        $this->assertSame('Logged', ThreatEventPresentation::actionLabel('log'));
    }
}
