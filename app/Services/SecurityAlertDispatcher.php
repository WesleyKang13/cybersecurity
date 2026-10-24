<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Company;
use App\Models\User;
use App\Notifications\SecurityAlertNotification;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

class SecurityAlertDispatcher
{
    private const TIMEOUT_SECONDS = 5;

    public function dispatch(Company $company, SecurityAlertNotification $notification): void
    {
        if ($company->status !== Company::STATUS_ACTIVE) {
            return;
        }

        foreach ($this->eligibleAlertUsers($company) as $user) {
            $this->dispatchForUser($user, $notification);
        }
    }

    /**
     * Deliver an attack-spike alert and report each channel outcome. This is
     * intentionally separate from dispatch() so existing alert types keep
     * their current best-effort delivery behavior.
     *
     * @param  list<string>  $alreadyDeliveredChannels
     * @return array{delivered: list<string>, failed: list<string>, configured_channels: int}
     */
    public function dispatchAttackSpike(
        Company $company,
        SecurityAlertNotification $notification,
        array $alreadyDeliveredChannels = []
    ): array {
        if ($company->status !== Company::STATUS_ACTIVE) {
            return ['delivered' => [], 'failed' => [], 'configured_channels' => 0];
        }

        $delivered = array_fill_keys($alreadyDeliveredChannels, true);
        $newlyDelivered = [];
        $failed = [];
        $configuredChannels = 0;

        foreach ($this->eligibleAlertUsers($company) as $user) {
            foreach ($this->configuredChannels($user) as $channel) {
                $configuredChannels++;
                $deliveryKey = "{$user->id}:{$channel}";

                if (isset($delivered[$deliveryKey])) {
                    continue;
                }

                if ($this->dispatchAttackSpikeChannel($user, $notification, $channel)) {
                    $delivered[$deliveryKey] = true;
                    $newlyDelivered[] = $deliveryKey;
                } else {
                    $failed[] = $deliveryKey;
                }
            }
        }

        return [
            'delivered' => array_values(array_unique($newlyDelivered)),
            'failed' => array_values(array_unique($failed)),
            'configured_channels' => $configuredChannels,
        ];
    }

    private function dispatchForUser(User $user, SecurityAlertNotification $notification): void
    {
        if ($user->security_alert_email_enabled && filled($user->email)) {
            $this->sendEmail($user, $notification);
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

    private function dispatchAttackSpikeChannel(
        User $user,
        SecurityAlertNotification $notification,
        string $channel
    ): bool {
        return match ($channel) {
            'email' => $this->sendEmail($user, $notification),
            'slack' => $this->postWebhook(
                url: (string) $user->security_alert_slack_webhook_url,
                payload: $notification->toSlackPayload(),
                channel: 'Slack',
                userId: $user->id
            ),
            'discord' => $this->postWebhook(
                url: (string) $user->security_alert_discord_webhook_url,
                payload: $notification->toDiscordPayload(),
                channel: 'Discord',
                userId: $user->id
            ),
            'telegram' => $this->postTelegram(
                botToken: (string) $user->security_alert_telegram_bot_token,
                chatId: (string) $user->security_alert_telegram_chat_id,
                payload: $notification->toTelegramPayload(),
                userId: $user->id
            ),
        };
    }

    /**
     * @return list<string>
     */
    private function configuredChannels(User $user): array
    {
        $channels = [];

        if ($user->security_alert_email_enabled && filled($user->email)) {
            $channels[] = 'email';
        }

        if ($user->security_alert_slack_enabled && filled($user->security_alert_slack_webhook_url)) {
            $channels[] = 'slack';
        }

        if ($user->security_alert_discord_enabled && filled($user->security_alert_discord_webhook_url)) {
            $channels[] = 'discord';
        }

        if (
            $user->security_alert_telegram_enabled
            && filled($user->security_alert_telegram_bot_token)
            && filled($user->security_alert_telegram_chat_id)
        ) {
            $channels[] = 'telegram';
        }

        return $channels;
    }

    private function sendEmail(User $user, SecurityAlertNotification $notification): bool
    {
        try {
            $user->notify($notification);

            return true;
        } catch (Throwable $e) {
            Log::warning("Security alert email failed for user {$user->id}: {$e->getMessage()}");

            return false;
        }
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function postWebhook(string $url, array $payload, string $channel, int $userId): bool
    {
        try {
            Http::timeout(self::TIMEOUT_SECONDS)
                ->connectTimeout(self::TIMEOUT_SECONDS)
                ->acceptJson()
                ->post($url, $payload)
                ->throw();

            return true;
        } catch (ConnectionException $e) {
            Log::warning("Security alert {$channel} webhook timed out for user {$userId}: {$e->getMessage()}");
        } catch (Throwable $e) {
            Log::warning("Security alert {$channel} webhook failed for user {$userId}: {$e->getMessage()}");
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function postTelegram(string $botToken, string $chatId, array $payload, int $userId): bool
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

            return true;
        } catch (ConnectionException $e) {
            Log::warning("Security alert Telegram notification timed out for user {$userId}: {$e->getMessage()}");
        } catch (Throwable $e) {
            Log::warning("Security alert Telegram notification failed for user {$userId}: {$e->getMessage()}");
        }

        return false;
    }

    private function eligibleAlertUsers(Company $company)
    {
        $eligibleRoles = User::rolesForCompany($company);

        if ($eligibleRoles === []) {
            return collect();
        }

        return $company->users()
            ->whereIn('role', $eligibleRoles)
            ->where(function ($query): void {
                $query
                    ->where('security_alert_email_enabled', true)
                    ->orWhere('security_alert_slack_enabled', true)
                    ->orWhere('security_alert_discord_enabled', true)
                    ->orWhere('security_alert_telegram_enabled', true);
            })
            ->orderBy('id')
            ->get();
    }
}
