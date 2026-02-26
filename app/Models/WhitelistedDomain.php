<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class WhitelistedDomain extends Model
{
    use HasFactory;
    protected $fillable = [
        'domain',
        'description',
        'is_active',
    ];
}
