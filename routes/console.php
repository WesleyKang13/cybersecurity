<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('scan:all')->EveryMinute();
