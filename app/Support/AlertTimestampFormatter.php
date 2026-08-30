<?php

declare(strict_types=1);

namespace App\Support;

use Carbon\CarbonImmutable;
use DateTimeInterface;

final class AlertTimestampFormatter
{
    public function format(DateTimeInterface $timestamp): string
    {
        return CarbonImmutable::instance($timestamp)
            ->setTimezone($this->timezone())
            ->format('j M Y, g:i A');
    }

    public function timezone(): string
    {
        $configuredTimezone = trim((string) config('security.alerts.timezone', ''));

        return $configuredTimezone !== ''
            ? $configuredTimezone
            : (string) config('app.timezone', 'UTC');
    }
}
