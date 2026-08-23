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
        $this->assertStringContainsString("reason: 'Authentication failed'", $this->guide);
        $this->assertStringNotContainsString("'password' =>", $this->guide);
        $this->assertStringContainsString('Never read or transmit $event->credentials', $this->guide);
    }
}
