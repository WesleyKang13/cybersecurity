<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class ScannedEmail extends Model
{
    use SoftDeletes;

    public const CLIENT_REVIEW_SEVERITIES = ['high', 'critical'];

    // Allow these fields to be saved
    protected $fillable = [
        'user_id',
        'google_message_id',
        'subject',
        'sender',
        'snippet',
        'is_threat',
        'detection_layer',
        'severity',
        'reason',
        'risk_score',
        'is_quarantined',
        'verdict',
        'threat_category',
        'analysis_chain',
        'final_reasoning',
        'origin_trace',
    ];

    protected $casts = [
        'is_threat' => 'boolean',
        'is_quarantined' => 'boolean',
        'analysis_chain' => 'array',
        'origin_trace' => 'array',
        'admin_reviewed_at' => 'datetime',
        'subject' => 'encrypted',
        'sender' => 'encrypted',
        'snippet' => 'encrypted',
    ];

    // Link back to the User
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function adminReviewedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'admin_reviewed_by_user_id');
    }

    public function scopeClientReviewable(Builder $query): Builder
    {
        return $query
            ->where('is_threat', true)
            ->whereIn('severity', [
                ...self::CLIENT_REVIEW_SEVERITIES,
                ...array_map('strtoupper', self::CLIENT_REVIEW_SEVERITIES),
            ]);
    }

    public function scopeForCompany(Builder $query, int $companyId): Builder
    {
        return $query->whereHas(
            'user',
            fn (Builder $userQuery) => $userQuery->where('company_id', $companyId)
        );
    }
}
