<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScannedSms extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'content',
        'is_threat',
        'risk_score',
        'type',
        'explanation',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
