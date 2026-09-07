<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('gemini-api', fn () => Limit::perMinute((int) config('services.gemini.requests_per_minute', 4))->by('gemini-provider'));

        if ($this->app->environment('production')) {
            URL::forceScheme('https');
        }
    }
}
