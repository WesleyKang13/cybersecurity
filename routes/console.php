<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('scan:all')->everyMinute()->withoutOverlapping();
Schedule::command('emails:cleanup')->daily();
