<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class OAuthToken extends Model
{
    protected $table = 'oauth_tokens';
    protected $fillable = [
        'company_id',
        'user_id',
        'provider',
        'access_token',
        'refresh_token',
        'expires_at'
    ];

    // Security: Automatically encrypt these when saving to DB
    protected $casts = [
        'access_token' => 'encrypted',
        'refresh_token' => 'encrypted',
        'expires_at' => 'datetime',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}
