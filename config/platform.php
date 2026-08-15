<?php

use App\Models\User;

$parseEmails = static fn (string $emails): array => array_values(array_filter(array_map(
    static fn (string $email): string => strtolower(trim($email)),
    explode(',', $emails)
)));

$operatorRoles = [];

foreach ($parseEmails((string) env('PLATFORM_OWNER_EMAILS', '')) as $email) {
    $operatorRoles[$email] = User::ROLE_PLATFORM_OWNER;
}

foreach ($parseEmails((string) env('PLATFORM_STAFF_EMAILS', '')) as $email) {
    if (isset($operatorRoles[$email])) {
        throw new LogicException("Platform operator {$email} is configured as both owner and staff.");
    }

    $operatorRoles[$email] = User::ROLE_PLATFORM_STAFF;
}

return [
    'company' => [
        'name' => env('PLATFORM_COMPANY_NAME'),
        'domain' => env('PLATFORM_COMPANY_DOMAIN'),
    ],

    'operator_roles' => $operatorRoles,
];
