<?php

use Illuminate\Support\Facades\Schedule;
use App\Models\User;
use App\Jobs\ScanGmailJob;

Schedule::command('scan:all')->everyTenMinutes();
