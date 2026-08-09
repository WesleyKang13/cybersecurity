<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class MonitoredDomain extends Model
{
    use HasFactory;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'domain',
        'is_active',
        'is_owned',
        'cloudflare_zone_id',
        'last_checked_at',
        'ssl_certificate_info',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
            'is_owned' => 'boolean',
            'last_checked_at' => 'datetime',
            'ssl_certificate_info' => 'array',
        ];
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
}
