<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class SecurityOperationsPresentationTest extends TestCase
{
    public function test_tier_three_management_and_activity_copy_are_explicit_about_local_enforcement(): void
    {
        $component = file_get_contents(__DIR__.'/../../resources/js/Pages/Admin/BlockedIpsIndex.jsx');
        $this->assertIsString($component);

        foreach (['Tier 3 IP Block Management', 'Blocked IP Activity', 'enforce it locally', 'does not indicate that access succeeded'] as $label) {
            $this->assertStringContainsString($label, $component);
        }
    }

    public function test_universal_scan_ui_uses_queued_status_and_polling_feedback(): void
    {
        $component = file_get_contents(__DIR__.'/../../resources/js/Pages/DnsSecurity/Index.jsx');
        $this->assertIsString($component);

        foreach ([
            "['queued', 'running']",
            'Scanning…',
            "route('dns-security.scan-statuses')",
            'pollScanStatuses',
            'universalScan.error',
        ] as $label) {
            $this->assertStringContainsString($label, $component);
        }

        $this->assertStringNotContainsString("only: ['domains', 'recentLogs']", $component);
    }

    public function test_threat_mitigation_ui_does_not_offer_a_duplicate_or_cross_tier_block_action(): void
    {
        $component = file_get_contents(__DIR__.'/../../resources/js/Pages/DnsSecurity/Index.jsx');
        $this->assertIsString($component);

        foreach (['canBlockThreat', 'Already Blocked', 'mitigation.label', 'mitigation.detail'] as $label) {
            $this->assertStringContainsString($label, $component);
        }
    }
}
