<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'company_id',
        'role',
        'token',
        'google_access_token',
        'google_refresh_token',
        'google_token_expires_at',
        'auto_quarantine',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'token',
        'google_access_token',
        'google_refresh_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'token' => 'array',
            'google_access_token' => 'encrypted',
            'google_refresh_token' => 'encrypted',
            'google_token_expires_at' => 'datetime',
            'auto_quarantine' => 'boolean',
        ];
    }

    // A user belongs to one company
    public function company()
    {
        return $this->belongsTo(Company::class);
    }

    // A user might have a connected Gmail token
    public function token()
    {
        return $this->hasOne(OAuthToken::class);
    }

    // Helper: Check if user is an Admin
    public function isAdmin(): bool
    {
        return $this->role === 'admin';
    }
    public function scannedEmails()
    {
        return $this->hasMany(ScannedEmail::class);
    }
}
