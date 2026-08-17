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

    public const ROLE_PLATFORM_OWNER = 'platform_owner';

    public const ROLE_PLATFORM_STAFF = 'platform_staff';

    public const ROLE_CLIENT_ADMIN = 'client_admin';

    public const ROLE_CLIENT_USER = 'client_user';

    public const LEGACY_ROLE_ADMIN = 'admin';

    public const LEGACY_ROLE_USER = 'user';

    public const LEGACY_ROLE_MEMBER = 'member';

    public const CANONICAL_ROLES = [
        self::ROLE_PLATFORM_OWNER,
        self::ROLE_PLATFORM_STAFF,
        self::ROLE_CLIENT_ADMIN,
        self::ROLE_CLIENT_USER,
    ];

    public const CLIENT_ROLES = [
        self::ROLE_CLIENT_ADMIN,
        self::ROLE_CLIENT_USER,
    ];

    public const CLIENT_ASSIGNABLE_TRANSITIONAL_ROLES = [
        self::ROLE_CLIENT_ADMIN,
        self::ROLE_CLIENT_USER,
        self::LEGACY_ROLE_USER,
        self::LEGACY_ROLE_MEMBER,
    ];

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

    public function isPlatformOwner(): bool
    {
        return $this->role === self::ROLE_PLATFORM_OWNER;
    }

    public function isPlatformStaff(): bool
    {
        return $this->role === self::ROLE_PLATFORM_STAFF;
    }

    public function isClientAdmin(): bool
    {
        return $this->role === self::ROLE_CLIENT_ADMIN;
    }

    public function isClientUser(): bool
    {
        return $this->role === self::ROLE_CLIENT_USER;
    }

    public function isPlatformUser(): bool
    {
        return $this->isPlatformOwner() || $this->isPlatformStaff();
    }

    public function belongsToPlatformCompany(): bool
    {
        return $this->belongsToCompanyType(Company::TYPE_PLATFORM);
    }

    public function belongsToClientCompany(): bool
    {
        return $this->belongsToCompanyType(Company::TYPE_CLIENT);
    }

    public function belongsToActivePlatformCompany(): bool
    {
        return $this->belongsToActiveCompanyType(Company::TYPE_PLATFORM);
    }

    public function belongsToActiveClientCompany(): bool
    {
        return $this->belongsToActiveCompanyType(Company::TYPE_CLIENT);
    }

    public function hasPlatformAccess(): bool
    {
        return $this->isPlatformUser() && $this->belongsToActivePlatformCompany();
    }

    public function hasPlatformOwnerAccess(): bool
    {
        return $this->isPlatformOwner() && $this->belongsToActivePlatformCompany();
    }

    public function hasClientAdminPortalAccess(): bool
    {
        return $this->isClientAdmin() && $this->belongsToActiveClientCompany();
    }

    public function hasClientUserPortalAccess(): bool
    {
        return $this->isClientUser() && $this->belongsToActiveClientCompany();
    }

    public function isEligibleForClientAssignment(): bool
    {
        return $this->company_id === null
            && in_array($this->role, self::CLIENT_ASSIGNABLE_TRANSITIONAL_ROLES, true);
    }

    /**
     * Backward-compatible alias for existing application code.
     */
    public function isAdmin(): bool
    {
        return $this->hasPlatformAccess();
    }

    public static function isRoleValidForCompany(string $role, ?Company $company): bool
    {
        return in_array($role, self::rolesForCompany($company), true);
    }

    /**
     * @return array<int, string>
     */
    public static function rolesForCompany(?Company $company): array
    {
        return match ($company?->type) {
            Company::TYPE_PLATFORM => [
                self::ROLE_PLATFORM_OWNER,
                self::ROLE_PLATFORM_STAFF,
            ],
            Company::TYPE_CLIENT => [
                self::ROLE_CLIENT_ADMIN,
                self::ROLE_CLIENT_USER,
            ],
            default => [],
        };
    }

    public function scannedEmails()
    {
        return $this->hasMany(ScannedEmail::class);
    }

    private function belongsToCompanyType(string $companyType): bool
    {
        return $this->relatedCompany()?->type === $companyType;
    }

    private function belongsToActiveCompanyType(string $companyType): bool
    {
        $company = $this->relatedCompany();

        return $company?->type === $companyType
            && $company->status === Company::STATUS_ACTIVE;
    }

    private function relatedCompany(): ?Company
    {
        if ($this->company_id === null) {
            return null;
        }

        if (! $this->relationLoaded('company')) {
            $this->setRelation('company', $this->company()->first());
        }

        return $this->company;
    }
}
