<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->boolean('security_alert_email_enabled')->default(false)->after('auto_quarantine');
            $table->boolean('security_alert_slack_enabled')->default(false)->after('security_alert_email_enabled');
            $table->boolean('security_alert_discord_enabled')->default(false)->after('security_alert_slack_enabled');
            $table->boolean('security_alert_telegram_enabled')->default(false)->after('security_alert_discord_enabled');
            $table->text('security_alert_slack_webhook_url')->nullable()->after('security_alert_telegram_enabled');
            $table->text('security_alert_discord_webhook_url')->nullable()->after('security_alert_slack_webhook_url');
            $table->text('security_alert_telegram_bot_token')->nullable()->after('security_alert_discord_webhook_url');
            $table->text('security_alert_telegram_chat_id')->nullable()->after('security_alert_telegram_bot_token');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn([
                'security_alert_email_enabled',
                'security_alert_slack_enabled',
                'security_alert_discord_enabled',
                'security_alert_telegram_enabled',
                'security_alert_slack_webhook_url',
                'security_alert_discord_webhook_url',
                'security_alert_telegram_bot_token',
                'security_alert_telegram_chat_id',
            ]);
        });
    }
};
