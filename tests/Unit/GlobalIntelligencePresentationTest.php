<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class GlobalIntelligencePresentationTest extends TestCase
{
    private string $component;

    private string $dashboard;

    protected function setUp(): void
    {
        parent::setUp();

        $component = file_get_contents(__DIR__.'/../../resources/js/Pages/Admin/Partials/GlobalIntelligencePanel.jsx');
        $dashboard = file_get_contents(__DIR__.'/../../resources/js/Pages/Admin/Dashboard.jsx');
        $this->assertIsString($component);
        $this->assertIsString($dashboard);
        $this->component = $component;
        $this->dashboard = $dashboard;
    }

    public function test_workspace_is_ip_and_attacker_centric(): void
    {
        foreach (['Search IP', 'Investigate', 'Attacker identity', 'CyberSafe observations', 'Top Attackers'] as $label) {
            $this->assertStringContainsString($label, $this->component);
        }

        foreach (['Country', 'Region / City', 'ISP', 'Organization', 'ASN', 'Hosting indicator', 'Proxy / VPN indicator'] as $field) {
            $this->assertStringContainsString($field, $this->component);
        }

        $this->assertStringContainsString('<GlobalIntelligencePanel topAttackers={top_attackers} />', $this->dashboard);
    }

    public function test_workspace_does_not_duplicate_the_threat_overview_event_experience(): void
    {
        foreach (['security_threat_events', 'selectedEvent', 'severityFilter', 'Threat detail', 'Sanitized Metadata', 'Export Global Threat Feed'] as $eventFeedFeature) {
            $this->assertStringNotContainsString($eventFeedFeature, $this->component);
        }
    }

    public function test_block_states_and_legacy_breakdowns_are_present(): void
    {
        foreach ([
            'Cloudflare IP Access Rule active',
            'Tier 3 global block-list entry',
            'Tier 3 domain block-list entry',
            'Cloudflare status not synced',
            'Verified Block Locations',
            'No verified block locations were found for this IP.',
            'Only active Cloudflare rules and stored Tier 3 block-list entries appear here.',
            'those zones are not shown as blocked',
            'Recent attacker activity',
            'unclassified',
        ] as $label) {
            $this->assertStringContainsString($label, $this->component);
        }

        $this->assertStringNotContainsString('blocked somewhere', strtolower($this->component));
    }
}
