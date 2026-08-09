<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class WebSecurityScan extends Model
{
    use HasFactory;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'monitored_domain_id',
        'http_status',
        'response_time_ms',
        'ssl_valid',
        'ssl_expires_at',
        'ssl_issuer',
        'missing_headers',
        'security_score',
        'detected_issues',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'http_status' => 'integer',
            'response_time_ms' => 'integer',
            'ssl_valid' => 'boolean',
            'ssl_expires_at' => 'datetime',
            'missing_headers' => 'array',
            'security_score' => 'integer',
            'detected_issues' => 'array',
        ];
    }

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }
}
