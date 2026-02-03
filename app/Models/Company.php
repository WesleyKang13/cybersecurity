<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Company extends Model
{
    // Allow these fields to be filled safely
    protected $fillable = ['name','domain','is_active'];

    // A company has many employees (users)
    public function users(): HasMany {
        return $this->hasMany(User::class);
    }

    // A company has many connected gmail accounts
    public function tokens(): HasMany {
        return $this->hasMany(OAuthToken::class);
    }
}
