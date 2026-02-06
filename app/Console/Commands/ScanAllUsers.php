<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\User;
use App\Jobs\ScanGmailJob;

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
        $this->info('Starting automated security scan...');

        // 1. Find all users who have a Google Token
        $users = User::whereNotNull('token')->get();

        if ($users->isEmpty()) {
            $this->warn('No connected users found.');
            return;
        }

        $this->info("Found {$users->count()} users. Dispatching jobs...");

        // 2. Loop through each user and trigger the Job
        foreach ($users as $user) {
            ScanGmailJob::dispatch($user);
            $this->info(" -> Dispatched scan for: {$user->name}");


        }

        $this->info('All jobs dispatched successfully!');
    }
}
