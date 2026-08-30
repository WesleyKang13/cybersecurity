<?php

declare(strict_types=1);

namespace App\Notifications;

use App\Support\AlertTimestampFormatter;
use Carbon\CarbonImmutable;
use DateTimeInterface;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SecurityAlertNotification extends Notification
{
    use Queueable;

    private readonly CarbonImmutable $detectedAt;

    /**
     * @param  array<string, int|string>  $details
     */
    public function __construct(
        public readonly string $alertType,
        public readonly string $domainName,
        public readonly string $severity,
        public readonly string $message,
        ?DateTimeInterface $detectedAt = null,
        public readonly array $details = []
    ) {
        $this->detectedAt = $detectedAt !== null
            ? CarbonImmutable::instance($detectedAt)->utc()
            : CarbonImmutable::now('UTC');
    }

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $formatter = app(AlertTimestampFormatter::class);
        $mail = (new MailMessage)
            ->subject($this->subjectLine())
            ->greeting($this->heading())
            ->line("Severity: {$this->severity}")
            ->line("Domain: {$this->domainName}")
            ->line('Detected: '.$formatter->format($this->detectedAt))
            ->line('Timezone: '.$formatter->timezone());

        foreach ($this->detailLines() as $line) {
            $mail->line($line);
        }

        return $mail->line($this->actionLine());
    }

    /**
     * @return array<string, mixed>
     */
    public function toSlackPayload(): array
    {
        return [
            'text' => $this->toMarkdownText(),
            'blocks' => [
                [
                    'type' => 'section',
                    'text' => [
                        'type' => 'mrkdwn',
                        'text' => $this->toMarkdownText(),
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toDiscordPayload(): array
    {
        return [
            'content' => $this->toMarkdownText(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toTelegramPayload(): array
    {
        return [
            'text' => $this->toMarkdownText(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        $formatter = app(AlertTimestampFormatter::class);

        return [
            'alert_type' => $this->alertType,
            'domain_name' => $this->domainName,
            'severity' => $this->severity,
            'message' => $this->message,
            'timestamp' => $this->detectedAt->toIso8601String(),
            'detected_at' => $this->detectedAt->toIso8601String(),
            'detected_at_formatted' => $formatter->format($this->detectedAt),
            'timezone' => $formatter->timezone(),
            'details' => $this->details,
        ];
    }

    public function toMarkdownText(): string
    {
        $formatter = app(AlertTimestampFormatter::class);
        $lines = [
            "# {$this->heading()}",
            '',
            "**Severity:** {$this->severity}",
            "**Domain:** {$this->domainName}",
            '**Detected:** '.$formatter->format($this->detectedAt),
            '**Timezone:** '.$formatter->timezone(),
            '',
            '## Details',
            ...$this->detailLines(),
            '',
            '## Action',
            $this->actionLine(),
        ];

        return implode("\n", $lines);
    }

    public function subjectLine(): string
    {
        return "[{$this->severity}] {$this->readableAlertType()} - {$this->domainName}";
    }

    public function heading(): string
    {
        return match ($this->alertType) {
            'dns_drift' => 'DNS Drift Alert',
            'ssl_warning' => 'SSL Certificate Alert',
            'attack_spike' => 'Attack Spike Alert',
            'auto_ban' => 'Auto-Ban Alert',
            default => 'Security Alert',
        };
    }

    private function readableAlertType(): string
    {
        return match ($this->alertType) {
            'attack_spike' => 'Attack Spike Detected',
            'ssl_warning' => 'SSL Certificate Expiry',
            'dns_drift' => 'DNS Drift Detected',
            'auto_ban' => 'Auto-Ban Triggered',
            default => 'Security Alert',
        };
    }

    /**
     * @return list<string>
     */
    private function detailLines(): array
    {
        if ($this->alertType !== 'attack_spike') {
            return [$this->message];
        }

        $eventsInWindow = (int) ($this->details['events_in_window'] ?? 0);
        $windowMinutes = (int) ($this->details['monitoring_window_minutes'] ?? 0);
        $highThreshold = (int) ($this->details['high_threshold'] ?? 0);
        $criticalThreshold = (int) ($this->details['critical_threshold'] ?? 0);
        $lines = [
            "{$eventsInWindow} security events were detected during the last {$windowMinutes} minutes.",
            "HIGH threshold: {$highThreshold} events",
            "CRITICAL threshold: {$criticalThreshold} events",
        ];

        if (array_key_exists('new_events_added_during_latest_sync', $this->details)) {
            $lines[] = 'New events added during latest sync: '
                .(int) $this->details['new_events_added_during_latest_sync'];
        }

        return $lines;
    }

    private function actionLine(): string
    {
        return $this->alertType === 'attack_spike'
            ? 'Review Threat Overview for attacker IPs, requested paths, countries and mitigation actions.'
            : 'Review the DNS Security Manager dashboard for remediation details.';
    }
}
