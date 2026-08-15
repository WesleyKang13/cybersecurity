<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Str;

class MonitoredDomain extends Model
{
    use HasFactory;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'domain',
        'infrastructure_type',
        'app_secret_token',
        'is_active',
        'is_owned',
        'cloudflare_zone_id',
        'auto_ban_threshold',
        'last_checked_at',
        'ssl_certificate_info',
    ];

    /**
     * @var list<string>
     */
    protected $hidden = [
        'app_secret_token',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'infrastructure_type' => 'string',
            'is_active' => 'boolean',
            'is_owned' => 'boolean',
            'auto_ban_threshold' => 'integer',
            'last_checked_at' => 'datetime',
            'ssl_certificate_info' => 'array',
        ];
    }

    protected static function booted(): void
    {
        static::creating(function (MonitoredDomain $domain): void {
            if ($domain->infrastructure_type !== 'app_middleware' || filled($domain->app_secret_token)) {
                return;
            }

            $domain->app_secret_token = static::generateUniqueAppSecretToken();
        });
    }

    public function dnsSecurityLogs(): HasMany
    {
        return $this->hasMany(DnsSecurityLog::class);
    }

    public function webSecurityScans(): HasMany
    {
        return $this->hasMany(WebSecurityScan::class);
    }

    public function latestWebSecurityScan(): HasOne
    {
        return $this->hasOne(WebSecurityScan::class)->latestOfMany();
    }

    public function securityThreatLogs(): HasMany
    {
        return $this->hasMany(SecurityThreatLog::class);
    }

    public function blockedIps(): HasMany
    {
        return $this->hasMany(BlockedIp::class);
    }

    private static function generateUniqueAppSecretToken(): string
    {
        do {
            $token = Str::random(64);
        } while (static::query()->where('app_secret_token', $token)->exists());

        return $token;
    }
}
