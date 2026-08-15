<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('scan:all')->everyMinute()->withoutOverlapping();
Schedule::command('app:scan-dns')->twiceDaily()->withoutOverlapping();
Schedule::command('emails:cleanup')->daily();

Schedule::command('app:sync-threats')->everyTenMinutes();
