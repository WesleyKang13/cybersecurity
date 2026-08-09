<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;
use App\Notifications\SecurityAlertNotification;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class SecurityAlertDispatcher
{
    private const TIMEOUT_SECONDS = 5;

    public function dispatch(SecurityAlertNotification $notification): void
    {
        $users = User::query()
            ->where(function ($query): void {
                $query
                    ->where('security_alert_email_enabled', true)
                    ->orWhere('security_alert_slack_enabled', true)
                    ->orWhere('security_alert_discord_enabled', true)
                    ->orWhere('security_alert_telegram_enabled', true);
            })
            ->orderBy('id')
            ->get();

        foreach ($users as $user) {
            $this->dispatchForUser($user, $notification);
        }
    }

    private function dispatchForUser(User $user, SecurityAlertNotification $notification): void
    {
        if ($user->security_alert_email_enabled && filled($user->email)) {
            try {
                $user->notify($notification);
            } catch (Throwable $e) {
                Log::warning("Security alert email failed for user {$user->id}: {$e->getMessage()}");
            }
        }

        if ($user->security_alert_slack_enabled && filled($user->security_alert_slack_webhook_url)) {
            $this->postWebhook(
                url: (string) $user->security_alert_slack_webhook_url,
                payload: $notification->toSlackPayload(),
                channel: 'Slack',
                userId: $user->id
            );
        }

        if ($user->security_alert_discord_enabled && filled($user->security_alert_discord_webhook_url)) {
            $this->postWebhook(
                url: (string) $user->security_alert_discord_webhook_url,
                payload: $notification->toDiscordPayload(),
                channel: 'Discord',
                userId: $user->id
            );
        }

        if (
            $user->security_alert_telegram_enabled
            && filled($user->security_alert_telegram_bot_token)
            && filled($user->security_alert_telegram_chat_id)
        ) {
            $this->postTelegram(
                botToken: (string) $user->security_alert_telegram_bot_token,
                chatId: (string) $user->security_alert_telegram_chat_id,
                payload: $notification->toTelegramPayload(),
                userId: $user->id
            );
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function postWebhook(string $url, array $payload, string $channel, int $userId): void
    {
        try {
            Http::timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->acceptJson()
                ->post($url, $payload)
                ->throw();
        } catch (ConnectionException $e) {
            Log::warning("Security alert {$channel} webhook timed out for user {$userId}: {$e->getMessage()}");
        } catch (Throwable $e) {
            Log::warning("Security alert {$channel} webhook failed for user {$userId}: {$e->getMessage()}");
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function postTelegram(string $botToken, string $chatId, array $payload, int $userId): void
    {
        try {
            Http::timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->acceptJson()
                ->post("https://api.telegram.org/bot{$botToken}/sendMessage", [
                    'chat_id' => $chatId,
                    'text' => (string) ($payload['text'] ?? ''),
                ])
                ->throw();
        } catch (ConnectionException $e) {
            Log::warning("Security alert Telegram notification timed out for user {$userId}: {$e->getMessage()}");
        } catch (Throwable $e) {
            Log::warning("Security alert Telegram notification failed for user {$userId}: {$e->getMessage()}");
        }
    }
}
