<?php

declare(strict_types=1);

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SecurityAlertNotification extends Notification
{
    use Queueable;

    public function __construct(
        public readonly string $alertType,
        public readonly string $domainName,
        public readonly string $severity,
        public readonly string $message
    ) {
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
        return (new MailMessage())
            ->subject($this->subjectLine())
            ->greeting($this->heading())
            ->line("Severity: {$this->severity}")
            ->line("Domain: {$this->domainName}")
            ->line('Timestamp: ' . now()->toDayDateTimeString())
            ->line($this->message)
            ->line('Review the DNS Security Manager dashboard for remediation details.');
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
     * @return array<string, string>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'alert_type' => $this->alertType,
            'domain_name' => $this->domainName,
            'severity' => $this->severity,
            'message' => $this->message,
            'timestamp' => now()->toIso8601String(),
        ];
    }

    public function toMarkdownText(): string
    {
        return implode("\n", [
            "# {$this->heading()}",
            '',
            "**Severity:** {$this->severity}",
            "**Domain:** {$this->domainName}",
            '**Timestamp:** ' . now()->toDayDateTimeString(),
            '',
            '## Details',
            $this->message,
            '',
            '## Action',
            'Review the DNS Security Manager dashboard and investigate the affected domain.',
        ]);
    }

    public function subjectLine(): string
    {
        return "[{$this->severity}] {$this->readableAlertType()} - {$this->domainName}";
    }

    public function heading(): string
    {
        return 'DNS Security Alert';
    }

    private function readableAlertType(): string
    {
        return match ($this->alertType) {
            'attack_spike' => 'Attack Spike Detected',
            'ssl_warning' => 'SSL Certificate Warning',
            'dns_drift' => 'DNS Baseline Drift',
            default => 'Security Alert',
        };
    }
}
