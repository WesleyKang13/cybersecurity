<?php

namespace App\Console\Commands;

use App\Jobs\ScanGmailJob;
use App\Models\User;
use Illuminate\Console\Command;

class ScanAllUsers extends Command
{
    /**
     * The name and signature of the console command.
     * e.g., run "php artisan scan:all" in the terminal
     */
    protected $signature = 'scan:all';

    /**
     * The console command description.
     */
    protected $description = 'Dispatch scan jobs for all connected users';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $dispatchedJobs = 0;

        User::query()
            ->where('auto_quarantine', true)
            ->where(function ($query) {
                $query
                    ->whereNotNull('google_access_token')
                    ->orWhereNotNull('google_refresh_token');
            })
            ->chunkById(100, function ($users) use (&$dispatchedJobs) {
                foreach ($users as $user) {
                    ScanGmailJob::dispatch($user);
                    $dispatchedJobs++;
                }
            });

        $this->info("Dispatched {$dispatchedJobs} Gmail scan job(s) for users with auto-quarantine enabled.");

        return self::SUCCESS;
    }
}
