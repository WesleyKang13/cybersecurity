<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScannedEmail extends Model
{
    // Allow these fields to be saved
    protected $fillable = [
        'user_id',
        'google_message_id',
        'subject',
        'sender',
        'snippet',
        'is_threat',
        'severity',
        'reason',
        'risk_score'
    ];

    // Link back to the User
    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
