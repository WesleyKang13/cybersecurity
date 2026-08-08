<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class ScannedEmail extends Model
{
    use SoftDeletes;
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
        'subject' => 'encrypted',
        'sender' => 'encrypted',
        'snippet' => 'encrypted',
    ];

    // Link back to the User
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
