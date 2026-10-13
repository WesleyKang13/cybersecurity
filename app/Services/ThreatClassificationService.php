<?php

declare(strict_types=1);

namespace App\Services;

final class ThreatClassificationService
{
    /**
     * Classifies only directly recognizable request paths. Everything else stays
     * unclassified rather than inferring intent or compromise.
     *
     * @return array{event_type: string, severity: string, reason: string}|null
     */
    public function classifyFromPath(?string $path): ?array
    {
        $normalizedPath = strtolower(rawurldecode(trim((string) $path)));

        if ($normalizedPath === '') {
            return null;
        }

        if (preg_match('#/(?:\.env|\.git)(?:[/.]|$)#', $normalizedPath) === 1) {
            $isEnvironmentFile = str_contains($normalizedPath, '/.env');

            return [
                'event_type' => $isEnvironmentFile ? 'environment_file_probe' : 'repository_file_probe',
                'severity' => 'high',
                'reason' => $isEnvironmentFile
                    ? 'Attempted request for a sensitive environment configuration path.'
                    : 'Attempted request for a sensitive repository path.',
            ];
        }

        if (preg_match('#/(?:wp-admin(?:/|$)|wp-login\.php$|xmlrpc\.php$)#', $normalizedPath) === 1) {
            return [
                'event_type' => 'wordpress_admin_probe',
                'severity' => 'medium',
                'reason' => 'Attempted request for a WordPress administrative endpoint.',
            ];
        }

        if (preg_match('#/(?:phpmyadmin|pma)(?:/|$)#', $normalizedPath) === 1) {
            return [
                'event_type' => 'admin_console_probe',
                'severity' => 'medium',
                'reason' => 'Attempted request for a database administration endpoint.',
            ];
        }

        if (preg_match('#/(?:cgi-bin|vendor/phpunit|actuator|server-status)(?:/|$)#', $normalizedPath) === 1) {
            return [
                'event_type' => 'exposed_service_probe',
                'severity' => 'high',
                'reason' => 'Attempted request for a commonly probed administrative or diagnostic endpoint.',
            ];
        }

        return null;
    }
}
