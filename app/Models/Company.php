<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Company extends Model
{
    public const TYPE_PLATFORM = 'platform';

    public const TYPE_CLIENT = 'client';

    public const STATUS_ACTIVE = 'active';

    public const STATUS_INACTIVE = 'inactive';

    // Allow these fields to be filled safely
    protected $fillable = [
        'name',
        'domain',
        'is_active',
        'type',
        'status',
    ];

    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
        ];
    }

    // A company has many employees (users)
    public function users(): HasMany
    {
        return $this->hasMany(User::class);
    }

    // A company has many connected gmail accounts
    public function tokens(): HasMany
    {
        return $this->hasMany(OAuthToken::class);
    }
}
