<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AttackSpikeAlert extends Model
{
    public const STATUS_PENDING = 'pending';

    public const STATUS_DELIVERED = 'delivered';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'company_id',
        'monitored_domain_id',
        'severity',
        'status',
        'detected_at',
        'events_in_window',
        'monitoring_window_minutes',
        'high_threshold',
        'critical_threshold',
        'new_events_added_during_latest_sync',
        'outcomes',
        'delivered_channels',
        'delivery_lock_token',
        'delivery_lock_expires_at',
        'last_attempt_at',
        'delivered_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'detected_at' => 'datetime',
            'events_in_window' => 'integer',
            'monitoring_window_minutes' => 'integer',
            'high_threshold' => 'integer',
            'critical_threshold' => 'integer',
            'new_events_added_during_latest_sync' => 'integer',
            'outcomes' => 'array',
            'delivered_channels' => 'array',
            'delivery_lock_expires_at' => 'datetime',
            'last_attempt_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }

    public function company(): BelongsTo
    {
        return $this->belongsTo(Company::class);
    }

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }
}
