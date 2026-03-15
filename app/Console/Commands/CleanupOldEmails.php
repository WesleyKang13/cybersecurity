<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\ScannedEmail;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

class CleanupOldEmails extends Command
{
    // This is the command you will type in the terminal to run it
    protected $signature = 'emails:cleanup';

    // A helpful description for other developers
    protected $description = 'Deletes scanned emails older than 14 days to comply with data retention policies.';

    public function handle()
    {

        // Calculate the exact date and time 14 days ago
        $cutoffDate = Carbon::now()->subDays(14);

        // Find and delete the records
        $deletedCount = ScannedEmail::where('created_at', '<', $cutoffDate)->delete();

        // Log it for your own server records
        $this->info("Successfully deleted {$deletedCount} old emails.");
    }
}
