<?php

declare(strict_types=1);

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class Tier3IntegrationGuideTest extends TestCase
{
    private string $guide;

    protected function setUp(): void
    {
        parent::setUp();

        $contents = file_get_contents(__DIR__.'/../../resources/js/Pages/Partials/Tier3IntegrationGuideModal.jsx');
        $this->assertIsString($contents);
        $this->guide = $contents;
    }

    public function test_existing_three_argument_client_calls_remain_supported(): void
    {
        $this->assertStringContainsString('?string $eventType = null', $this->guide);
        $this->assertStringContainsString('?string $severity = null', $this->guide);
        $this->assertStringContainsString('?string $reason = null', $this->guide);
        $this->assertStringContainsString('array $metadata = []', $this->guide);
    }

    public function test_middleware_examples_classify_each_existing_probe(): void
    {
        $expectedClassifications = [
            "'needle' => '.env'" => "'event_type' => 'environment_file_probe'",
            "'needle' => 'wp-admin'" => "'event_type' => 'wordpress_admin_probe'",
            "'needle' => 'phpmyadmin'" => "'event_type' => 'phpmyadmin_probe'",
            "'needle' => 'test-middleware'" => "'event_type' => 'test_probe'",
        ];

        foreach ($expectedClassifications as $needle => $eventType) {
            $needlePosition = strpos($this->guide, $needle);
            $eventTypePosition = strpos($this->guide, $eventType, $needlePosition ?: 0);

            $this->assertNotFalse($needlePosition, "Missing middleware signature: {$needle}");
            $this->assertNotFalse($eventTypePosition, "Missing classification: {$eventType}");
            $this->assertLessThan(250, $eventTypePosition - $needlePosition);
        }

        $this->assertStringContainsString("'local_only' => true", $this->guide);
        $this->assertStringContainsString("app()->environment('local')", $this->guide);
    }

    public function test_failed_login_example_never_transmits_credentials(): void
    {
        $this->assertStringContainsString('use Illuminate\\\\Auth\\\\Events\\\\Failed;', $this->guide);
        $this->assertStringContainsString("eventType: 'failed_login'", $this->guide);
        $this->assertStringContainsString("'account_exists' => \$accountExists", $this->guide);
        $this->assertStringContainsString("'target_role' => \$targetRole", $this->guide);
        $this->assertStringContainsString("'attempted_identifier_masked' => \$maskedIdentifier", $this->guide);
        $this->assertStringContainsString("'attempt_count' => \$attemptCount", $this->guide);
        $this->assertStringNotContainsString("'password' =>", $this->guide);
        $this->assertStringContainsString('Never read or transmit $event->credentials', $this->guide);
    }

    public function test_failed_login_example_masks_identifiers_before_reporting(): void
    {
        $this->assertStringContainsString('private function maskEmailIdentifier(mixed $value): ?string', $this->guide);
        $this->assertStringContainsString('FILTER_VALIDATE_EMAIL', $this->guide);
        $this->assertStringContainsString("return substr(\$localPart, 0, 1).'***@'.strtolower(\$domain);", $this->guide);
        $this->assertStringContainsString("'attempted_identifier_masked' => 'w***@company.com'", $this->guide);
        $this->assertStringNotContainsString("'attempted_identifier' =>", $this->guide);
    }

    public function test_failed_login_attempt_counter_is_optional_reporting_context_only(): void
    {
        $this->assertStringContainsString('Cache::add($key, 0, now()->addMinutes(self::ATTEMPT_WINDOW_MINUTES))', $this->guide);
        $this->assertStringContainsString('Cache::increment($key)', $this->guide);
        $this->assertStringContainsString("hash('sha256', \$ip.'|'", $this->guide);
        $this->assertStringContainsString('does not change login throttling', $this->guide);
        $this->assertStringNotContainsString('RateLimiter::hit', $this->guide);
        $this->assertStringNotContainsString('RateLimiter::clear', $this->guide);
        $this->assertStringNotContainsString('tooManyAttempts', $this->guide);
    }

    public function test_failed_login_severity_is_deterministic_and_never_critical(): void
    {
        $this->assertStringContainsString('$isPrivilegedTarget && $attemptCount >= 3', $this->guide);
        $this->assertStringContainsString('$attemptCount >= 5', $this->guide);
        $this->assertStringContainsString("severity: \$isHighSeverity ? 'high' : 'medium'", $this->guide);
        $this->assertStringNotContainsString("severity: 'critical'", $this->guide);
    }
}
