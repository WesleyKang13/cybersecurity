<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScannedUrl extends Model
{
    protected $fillable = ['url', 'is_malicious', 'malicious_votes'];
    protected $casts = ['is_malicious' => 'boolean'];
}
