<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class ScannedSms extends Model
{
    use HasFactory;
    use SoftDeletes;

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
