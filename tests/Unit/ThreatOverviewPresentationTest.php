<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class ThreatOverviewPresentationTest extends TestCase
{
    private string $component;

    protected function setUp(): void
    {
        parent::setUp();

        $contents = file_get_contents(__DIR__.'/../../resources/js/Pages/Admin/Partials/ThreatOverviewPanel.jsx');
        $this->assertIsString($contents);
        $this->component = $contents;
    }

    public function test_enriched_and_action_fields_have_separate_labels(): void
    {
        foreach (['Threat Type', 'Severity', 'Reason', 'Action Taken', 'Attacker IP', 'Targeted Path', 'Source', 'Application / Domain', 'Detected At', 'User Agent'] as $label) {
            $this->assertStringContainsString($label, $this->component);
        }

        $this->assertStringContainsString('selectedEvent.event_type', $this->component);
        $this->assertStringContainsString('selectedEvent.severity', $this->component);
        $this->assertStringContainsString('selectedEvent.reason', $this->component);
        $this->assertStringContainsString('selectedEvent.action_taken', $this->component);
    }

    public function test_legacy_events_have_explicit_non_invented_fallbacks(): void
    {
        $this->assertStringContainsString("eventTypeLabel = (value) => formatLabel(value, 'Generic Threat')", $this->component);
        $this->assertStringContainsString("CANONICAL_SEVERITIES.includes(normalized) ? normalized : 'unclassified'", $this->component);
        $this->assertStringContainsString("formatLabel(normalizedSeverity(value), 'Unclassified')", $this->component);
    }

    public function test_severity_filter_and_safe_metadata_presentation_are_present(): void
    {
        foreach (['critical', 'high', 'medium', 'low', 'unclassified'] as $severity) {
            $this->assertStringContainsString("'{$severity}'", $this->component);
        }

        $this->assertStringContainsString('Sanitized Metadata', $this->component);
        $this->assertStringContainsString('JSON.stringify(metadata, null, 2)', $this->component);
    }

    public function test_failed_login_target_context_is_presented_only_when_available(): void
    {
        foreach (['Account Target', 'Account exists', 'Role', 'Attempted account', 'Attempt count', 'Route:'] as $label) {
            $this->assertStringContainsString($label, $this->component);
        }

        $this->assertStringContainsString("event?.event_type === 'failed_login'", $this->component);
        $this->assertStringContainsString('selectedFailedLoginAccountContext.length > 0', $this->component);
        $this->assertStringContainsString("typeof metadata.account_exists === 'boolean'", $this->component);
        $this->assertStringContainsString('Number.isInteger(metadata.attempt_count)', $this->component);
    }
}
