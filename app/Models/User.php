<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'company_id',
        'role',
        'token',
        'google_access_token',
        'google_refresh_token',
        'google_token_expires_at',
        'auto_quarantine',
        'security_alert_email_enabled',
        'security_alert_slack_enabled',
        'security_alert_discord_enabled',
        'security_alert_telegram_enabled',
        'security_alert_slack_webhook_url',
        'security_alert_discord_webhook_url',
        'security_alert_telegram_bot_token',
        'security_alert_telegram_chat_id',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'token',
        'google_access_token',
        'google_refresh_token',
        'security_alert_slack_webhook_url',
        'security_alert_discord_webhook_url',
        'security_alert_telegram_bot_token',
        'security_alert_telegram_chat_id',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'token' => 'array',
            'google_access_token' => 'encrypted',
            'google_refresh_token' => 'encrypted',
            'google_token_expires_at' => 'datetime',
            'auto_quarantine' => 'boolean',
            'security_alert_email_enabled' => 'boolean',
            'security_alert_slack_enabled' => 'boolean',
            'security_alert_discord_enabled' => 'boolean',
            'security_alert_telegram_enabled' => 'boolean',
            'security_alert_slack_webhook_url' => 'encrypted',
            'security_alert_discord_webhook_url' => 'encrypted',
            'security_alert_telegram_bot_token' => 'encrypted',
            'security_alert_telegram_chat_id' => 'encrypted',
        ];
    }

    // A user belongs to one company
    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    // A user might have a connected Gmail token
    public function token()
    {
        return $this->hasOne(OAuthToken::class);
    }

    // Helper: Check if user is an Admin
    public function isAdmin(): bool
    {
        return $this->role === 'admin';
    }

    public function scannedEmails()
    {
        return $this->hasMany(ScannedEmail::class);
    }
}
