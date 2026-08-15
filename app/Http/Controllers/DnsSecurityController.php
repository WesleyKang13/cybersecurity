<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\DnsSecurityLog;
use App\Models\MonitoredDomain;
use App\Models\SecurityThreatLog;
use App\Services\CloudflareIpBlockService;
use App\Services\DnsScannerService;
use App\Services\IpIntelligenceService;
use App\Services\UniversalSecurityScannerService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;
use Throwable;

class DnsSecurityController extends Controller
{
    public function index(CloudflareIpBlockService $cloudflareIpBlockService): Response
    {
        $twentyFourHoursAgo = now()->subHours(24);
        $user = request()->user();
        $lastSynced = Cache::get('threats_last_synced');

        $recentThreatLogModels = SecurityThreatLog::query()
            ->with('monitoredDomain:id,domain')
            ->whereHas('monitoredDomain', fn ($query) => $query->where('is_owned', true))
            ->where('detected_at', '>=', $twentyFourHoursAgo)
            ->orderByDesc('detected_at')
            ->get();

        $threatLogsByDomain = $recentThreatLogModels->groupBy('monitored_domain_id');

        $domainModels = MonitoredDomain::query()
            ->with('latestWebSecurityScan')
            ->withCount([
                'dnsSecurityLogs as unresolved_logs_count' => fn ($query) => $query
                    ->whereNull('resolved_at')
                    ->where('status', '!=', 'secure'),
                'dnsSecurityLogs as critical_count' => fn ($query) => $query
                    ->whereNull('resolved_at')
                    ->where('severity', 'critical'),
                'dnsSecurityLogs as high_count' => fn ($query) => $query
                    ->whereNull('resolved_at')
                    ->where('severity', 'high'),
                'dnsSecurityLogs as warning_count' => fn ($query) => $query
                    ->whereNull('resolved_at')
                    ->where('severity', 'warning'),
                'securityThreatLogs as recent_events_count' => fn ($query) => $query
                    ->where('detected_at', '>=', $twentyFourHoursAgo),
            ])
            ->orderBy('domain')
            ->get();
        $domainModels->each->makeVisible('app_secret_token');

        $activeAccessRules = $this->loadActiveAccessRules($domainModels, $cloudflareIpBlockService);

        $domains = $domainModels
            ->map(function (MonitoredDomain $domain) use ($threatLogsByDomain): array {
                $webSecurityScan = $domain->latestWebSecurityScan;
                $recentThreats = $threatLogsByDomain
                    ->get($domain->id, collect())
                    ->take(5)
                    ->map(function (SecurityThreatLog $log): array {
                        return [
                            'id' => $log->id,
                            'attacker_ip' => $log->attacker_ip,
                            'country' => $log->country,
                            'path_targeted' => $log->path_targeted,
                            'action_taken' => $log->action_taken,
                            'threat_source' => $log->threat_source,
                            'detected_at' => $log->detected_at?->toIso8601String(),
                            'detected_at_formatted' => $log->detected_at?->diffForHumans() ?? 'Unknown',
                        ];
                    })
                    ->values();

                return [
                    'id' => $domain->id,
                    'domain' => $domain->domain,
                    'infrastructure_type' => $domain->infrastructure_type,
                    'app_secret_token' => $domain->app_secret_token,
                    'is_active' => $domain->is_active,
                    'is_owned' => $domain->is_owned,
                    'cloudflare_zone_id' => $domain->cloudflare_zone_id,
                    'auto_ban_threshold' => (int) ($domain->auto_ban_threshold ?? 10),
                    'last_checked_at' => $domain->last_checked_at?->toIso8601String(),
                    'last_checked_at_formatted' => $domain->last_checked_at
                        ? $domain->last_checked_at->diffForHumans()
                        : 'Never scanned',
                    'unresolved_logs_count' => (int) $domain->unresolved_logs_count,
                    'critical_count' => (int) $domain->critical_count,
                    'high_count' => (int) $domain->high_count,
                    'warning_count' => (int) $domain->warning_count,
                    'recent_events_count' => (int) $domain->recent_events_count,
                    'overall_health_status' => $this->determineOverallHealthStatus(
                        criticalCount: (int) $domain->critical_count,
                        highCount: (int) $domain->high_count,
                        warningCount: (int) $domain->warning_count
                    ),
                    'web_security_scan' => $webSecurityScan !== null ? [
                        'http_status' => $webSecurityScan->http_status,
                        'response_time_ms' => $webSecurityScan->response_time_ms,
                        'ssl_valid' => $webSecurityScan->ssl_valid,
                        'ssl_expires_at' => $webSecurityScan->ssl_expires_at?->toIso8601String(),
                        'ssl_expires_at_formatted' => $webSecurityScan->ssl_expires_at?->format('M j, Y'),
                        'ssl_issuer' => $webSecurityScan->ssl_issuer,
                        'missing_headers' => $webSecurityScan->missing_headers ?? [],
                        'security_score' => $webSecurityScan->security_score,
                        'detected_issues' => $webSecurityScan->detected_issues ?? [],
                        'scanned_at' => $webSecurityScan->created_at?->toIso8601String(),
                        'scanned_at_formatted' => $webSecurityScan->created_at?->diffForHumans(),
                    ] : null,
                    'recent_threats' => $recentThreats,
                ];
            })
            ->values();

        $recentLogs = DnsSecurityLog::query()
            ->with('monitoredDomain:id,domain')
            ->latest()
            ->take(150)
            ->get()
            ->map(function (DnsSecurityLog $log): array {
                return [
                    'id' => $log->id,
                    'domain' => $log->monitoredDomain?->domain ?? 'Unknown',
                    'record_type' => $log->record_type,
                    'expected_value' => $log->expected_value,
                    'current_value' => $log->current_value,
                    'severity' => $log->severity,
                    'status' => $log->status,
                    'description' => $log->description,
                    'resolved_at' => $log->resolved_at?->toIso8601String(),
                    'resolved_at_formatted' => $log->resolved_at?->diffForHumans(),
                    'created_at' => $log->created_at?->toIso8601String(),
                    'created_at_formatted' => $log->created_at?->diffForHumans() ?? 'Unknown',
                    'is_resolved' => $log->resolved_at !== null,
                ];
            })
            ->values();

        $recentThreatLogs = $recentThreatLogModels
            ->map(function (SecurityThreatLog $log): array {
                return [
                    'id' => $log->id,
                    'domain_id' => $log->monitored_domain_id,
                    'domain' => $log->monitoredDomain?->domain ?? 'Unknown',
                    'attacker_ip' => $log->attacker_ip,
                    'country' => $log->country,
                    'path_targeted' => $log->path_targeted,
                    'action_taken' => $log->action_taken,
                    'threat_source' => $log->threat_source,
                    'detected_at' => $log->detected_at?->toIso8601String(),
                    'detected_at_formatted' => $log->detected_at?->format('Y-m-d H:i:s T'),
                    'detected_at_relative' => $log->detected_at?->diffForHumans() ?? 'Unknown',
                ];
            })
            ->values();

        $threatAnalytics = [
            'hourly_attack_volume' => $this->buildHourlyAttackVolume($recentThreatLogModels, $twentyFourHoursAgo),
            'top_targeted_paths' => $this->buildTopTargetedPaths($recentThreatLogModels),
            'top_origin_countries' => $this->buildTopOriginCountries($recentThreatLogModels),
            'total_events' => $recentThreatLogModels->count(),
        ];

        return Inertia::render('DnsSecurity/Index', [
            'domains' => $domains,
            'recentLogs' => $recentLogs,
            'recentThreatLogs' => $recentThreatLogs,
            'activeAccessRules' => $activeAccessRules,
            'threatAnalytics' => $threatAnalytics,
            'last_synced_at' => $lastSynced instanceof Carbon ? $lastSynced->toIso8601String() : null,
            'alertSettings' => [
                'email_enabled' => (bool) ($user?->security_alert_email_enabled ?? false),
                'slack_enabled' => (bool) ($user?->security_alert_slack_enabled ?? false),
                'discord_enabled' => (bool) ($user?->security_alert_discord_enabled ?? false),
                'telegram_enabled' => (bool) ($user?->security_alert_telegram_enabled ?? false),
                'slack_webhook_url' => (string) ($user?->security_alert_slack_webhook_url ?? ''),
                'discord_webhook_url' => (string) ($user?->security_alert_discord_webhook_url ?? ''),
                'telegram_bot_token' => (string) ($user?->security_alert_telegram_bot_token ?? ''),
                'telegram_chat_id' => (string) ($user?->security_alert_telegram_chat_id ?? ''),
            ],
        ]);
    }

    public function store(
        Request $request,
        DnsScannerService $scanner,
        UniversalSecurityScannerService $webSecurityScanner
    ): RedirectResponse
    {
        $normalizedDomain = $this->normalizeDomainInput((string) $request->input('domain', ''));
        $infrastructureType = trim((string) $request->input('infrastructure_type', 'universal'));
        $normalizedZoneId = trim((string) $request->input('cloudflare_zone_id', ''));

        $validator = Validator::make(
            [
                'domain' => $normalizedDomain,
                'infrastructure_type' => $infrastructureType,
                'cloudflare_zone_id' => $normalizedZoneId,
            ],
            [
                'domain' => ['required', 'string', 'max:255', 'unique:monitored_domains,domain'],
                'infrastructure_type' => ['required', 'string', 'in:universal,cloudflare,app_middleware'],
                'cloudflare_zone_id' => ['nullable', 'string', 'max:255'],
            ]
        );

        $validator->after(function ($validator) use ($normalizedDomain, $infrastructureType, $normalizedZoneId): void {
            if (!$this->isValidDomain($normalizedDomain)) {
                $validator->errors()->add('domain', 'Enter a valid domain name.');
            }

            if ($infrastructureType === 'cloudflare' && $normalizedZoneId === '') {
                $validator->errors()->add('cloudflare_zone_id', 'A Cloudflare Zone ID is required for Cloudflare-backed infrastructure.');
            }
        });

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        $isOwned = match ($infrastructureType) {
            'cloudflare', 'app_middleware' => true,
            default => false,
        };

        $domain = MonitoredDomain::create([
            'domain' => $normalizedDomain,
            'infrastructure_type' => $infrastructureType,
            'is_owned' => $isOwned,
            'cloudflare_zone_id' => $infrastructureType === 'cloudflare' ? $normalizedZoneId : null,
            'is_active' => true,
        ]);

        try {
            $dnsResult = $scanner->scan($domain);
            $webResult = $webSecurityScanner->scan($domain);
            $integrationMessage = $infrastructureType === 'app_middleware'
                ? ' Integration credentials are ready in the domain settings view.'
                : '';

            return back()->with(
                'success',
                "Domain '{$normalizedDomain}' added and scanned successfully. {$dnsResult['vulnerability_count']} DNS issue(s) detected. Web security score: {$webResult['scan']->security_score}/100.{$integrationMessage}"
            );
        } catch (Throwable $e) {
            Log::error("Initial DNS scan failed for {$normalizedDomain}: {$e->getMessage()}");

            return back()->with(
                'error',
                "Domain '{$normalizedDomain}' was added, but the initial scan failed. You can retry manually."
            );
        }
    }

    public function destroy(MonitoredDomain $domain): RedirectResponse
    {
        $domainName = $domain->domain;
        $domain->delete();

        return back()->with('success', "Domain '{$domainName}' removed from DNS monitoring.");
    }

    public function scan(
        MonitoredDomain $domain,
        DnsScannerService $scanner,
        UniversalSecurityScannerService $webSecurityScanner
    ): RedirectResponse
    {
        try {
            $dnsResult = $scanner->scan($domain);
            $webResult = $webSecurityScanner->scan($domain);

            return back()->with(
                'success',
                "DNS and web security scan completed for '{$domain->domain}'. {$dnsResult['vulnerability_count']} DNS issue(s) detected. Web security score: {$webResult['scan']->security_score}/100."
            );
        } catch (Throwable $e) {
            Log::error("Manual DNS scan failed for {$domain->domain}: {$e->getMessage()}");

            return back()->with(
                'error',
                "DNS scan failed for '{$domain->domain}'. Please try again."
            );
        }
    }

    public function update(Request $request, MonitoredDomain $domain): RedirectResponse
    {
        $validatedAutoBanThreshold = Validator::make(
            [
                'auto_ban_threshold' => $request->input('auto_ban_threshold', $domain->auto_ban_threshold ?? 10),
            ],
            [
                'auto_ban_threshold' => ['required', 'integer', 'min:1'],
            ]
        )->validate();

        $autoBanThreshold = (int) $validatedAutoBanThreshold['auto_ban_threshold'];

        if ($domain->infrastructure_type === 'app_middleware') {
            $domain->update([
                'is_owned' => true,
                'cloudflare_zone_id' => null,
                'auto_ban_threshold' => $autoBanThreshold,
            ]);

            return back()->with('success', "Application middleware integration is active for '{$domain->domain}'.");
        }

        if ($domain->infrastructure_type === 'universal') {
            $domain->update([
                'is_owned' => false,
                'cloudflare_zone_id' => null,
                'auto_ban_threshold' => $autoBanThreshold,
            ]);

            return back()->with('success', "Universal posture scanning is active for '{$domain->domain}'.");
        }

        $normalizedZoneId = trim((string) $request->input('cloudflare_zone_id', ''));

        $validator = Validator::make(
            [
                'is_owned' => $request->boolean('is_owned'),
                'cloudflare_zone_id' => $normalizedZoneId,
            ],
            [
                'is_owned' => ['required', 'boolean'],
                'cloudflare_zone_id' => ['nullable', 'string', 'max:255'],
            ]
        );

        $validator->after(function ($validator) use ($request, $normalizedZoneId): void {
            if ($request->boolean('is_owned') && $normalizedZoneId === '') {
                $validator->errors()->add('cloudflare_zone_id', 'A Cloudflare Zone ID is required for owned infrastructure.');
            }
        });

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        $domain->update([
            'is_owned' => $request->boolean('is_owned'),
            'cloudflare_zone_id' => $request->boolean('is_owned') ? $normalizedZoneId : null,
            'auto_ban_threshold' => $autoBanThreshold,
        ]);

        return back()->with(
            'success',
            $request->boolean('is_owned')
                ? "Cloudflare settings saved for '{$domain->domain}'."
                : "'{$domain->domain}' is no longer marked as owned infrastructure."
        );
    }

    public function updateAlertSettings(Request $request): RedirectResponse
    {
        $user = $request->user();

        $payload = [
            'email_enabled' => $request->boolean('email_enabled'),
            'slack_enabled' => $request->boolean('slack_enabled'),
            'discord_enabled' => $request->boolean('discord_enabled'),
            'telegram_enabled' => $request->boolean('telegram_enabled'),
            'slack_webhook_url' => trim((string) $request->input('slack_webhook_url', '')),
            'discord_webhook_url' => trim((string) $request->input('discord_webhook_url', '')),
            'telegram_bot_token' => trim((string) $request->input('telegram_bot_token', '')),
            'telegram_chat_id' => trim((string) $request->input('telegram_chat_id', '')),
        ];

        $validator = Validator::make($payload, [
            'email_enabled' => ['required', 'boolean'],
            'slack_enabled' => ['required', 'boolean'],
            'discord_enabled' => ['required', 'boolean'],
            'telegram_enabled' => ['required', 'boolean'],
            'slack_webhook_url' => ['nullable', 'url', 'max:2048'],
            'discord_webhook_url' => ['nullable', 'url', 'max:2048'],
            'telegram_bot_token' => ['nullable', 'string', 'max:255'],
            'telegram_chat_id' => ['nullable', 'string', 'max:255'],
        ]);

        $validator->after(function ($validator) use ($payload): void {
            if ($payload['slack_enabled'] && $payload['slack_webhook_url'] === '') {
                $validator->errors()->add('slack_webhook_url', 'A Slack webhook URL is required when Slack alerts are enabled.');
            }

            if ($payload['discord_enabled'] && $payload['discord_webhook_url'] === '') {
                $validator->errors()->add('discord_webhook_url', 'A Discord webhook URL is required when Discord alerts are enabled.');
            }

            if ($payload['telegram_enabled'] && $payload['telegram_bot_token'] === '') {
                $validator->errors()->add('telegram_bot_token', 'A Telegram bot token is required when Telegram alerts are enabled.');
            }

            if ($payload['telegram_enabled'] && $payload['telegram_chat_id'] === '') {
                $validator->errors()->add('telegram_chat_id', 'A Telegram chat ID is required when Telegram alerts are enabled.');
            }
        });

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        $user->update([
            'security_alert_email_enabled' => $payload['email_enabled'],
            'security_alert_slack_enabled' => $payload['slack_enabled'],
            'security_alert_discord_enabled' => $payload['discord_enabled'],
            'security_alert_telegram_enabled' => $payload['telegram_enabled'],
            'security_alert_slack_webhook_url' => $payload['slack_webhook_url'] !== '' ? $payload['slack_webhook_url'] : null,
            'security_alert_discord_webhook_url' => $payload['discord_webhook_url'] !== '' ? $payload['discord_webhook_url'] : null,
            'security_alert_telegram_bot_token' => $payload['telegram_bot_token'] !== '' ? $payload['telegram_bot_token'] : null,
            'security_alert_telegram_chat_id' => $payload['telegram_chat_id'] !== '' ? $payload['telegram_chat_id'] : null,
        ]);

        return back()->with('success', 'Security alert notification settings updated.');
    }

    public function blockIp(Request $request, CloudflareIpBlockService $cloudflareIpBlockService): RedirectResponse
    {
        $validator = Validator::make(
            $request->all(),
            [
                'domain_id' => ['required', 'integer', 'exists:monitored_domains,id'],
                'ip_address' => ['required', 'ip'],
            ]
        );

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        $domain = MonitoredDomain::query()->findOrFail((int) $request->input('domain_id'));

        if (!$domain->is_owned || blank($domain->cloudflare_zone_id)) {
            throw ValidationException::withMessages([
                'block_ip' => 'This domain is not configured for Cloudflare mitigation.',
            ]);
        }

        $ipAddress = (string) $request->input('ip_address');
        $result = $cloudflareIpBlockService->blockIp((string) $domain->cloudflare_zone_id, $ipAddress);

        if (!$result['success']) {
            throw ValidationException::withMessages([
                'block_ip' => $result['message'],
            ]);
        }

        Log::info('Cloudflare IP mitigation deployed from DNS Security Dashboard.', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'attacker_ip' => $ipAddress,
            'cloudflare_rule_id' => $result['rule_id'],
            'blocked_at' => now()->toIso8601String(),
        ]);

        return back()->with('success', "Blocked {$ipAddress} on Cloudflare for '{$domain->domain}'.");
    }

    public function unblockIp(Request $request, CloudflareIpBlockService $cloudflareIpBlockService): RedirectResponse
    {
        $validator = Validator::make(
            $request->all(),
            [
                'domain_id' => ['required', 'integer', 'exists:monitored_domains,id'],
                'rule_id' => ['required', 'string', 'max:255'],
            ]
        );

        if ($validator->fails()) {
            throw new ValidationException($validator);
        }

        $domain = MonitoredDomain::query()->findOrFail((int) $request->input('domain_id'));

        if (!$domain->is_owned || blank($domain->cloudflare_zone_id)) {
            return back()->with('error', 'This domain is not configured for Cloudflare mitigation.');
        }

        $ruleId = trim((string) $request->input('rule_id'));
        $result = $cloudflareIpBlockService->deleteAccessRule((string) $domain->cloudflare_zone_id, $ruleId);

        if (!$result['success']) {
            return back()->with('error', $result['message']);
        }

        Log::info('Cloudflare IP mitigation removed from DNS Security Dashboard.', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'cloudflare_rule_id' => $ruleId,
            'unblocked_at' => now()->toIso8601String(),
        ]);

        return back()->with('success', "Removed Cloudflare access rule for '{$domain->domain}'.");
    }

    public function lookupIp(string $ip, IpIntelligenceService $ipIntelligenceService): JsonResponse
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return response()->json([
                'success' => false,
                'message' => 'Enter a valid IP address.',
            ], 422);
        }

        $result = $ipIntelligenceService->lookup($ip);

        if (($result['status'] ?? 'fail') !== 'success') {
            return response()->json([
                'success' => false,
                'message' => $result['message'] ?? 'IP intelligence lookup failed.',
                'data' => $result,
            ], 502);
        }

        return response()->json([
            'success' => true,
            'data' => $result,
        ]);
    }

    private function normalizeDomainInput(string $input): string
    {
        $trimmed = strtolower(trim($input));
        $host = parse_url($trimmed, PHP_URL_HOST);
        $normalized = is_string($host) ? $host : $trimmed;
        $normalized = preg_replace('#^https?://#', '', $normalized) ?? $normalized;
        $normalized = trim($normalized, " \t\n\r\0\x0B/");
        $normalized = preg_replace('/^www\./', '', $normalized) ?? $normalized;

        return strtolower($normalized);
    }

    private function isValidDomain(string $domain): bool
    {
        return $domain !== ''
            && filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false
            && str_contains($domain, '.');
    }

    private function determineOverallHealthStatus(int $criticalCount, int $highCount, int $warningCount): string
    {
        if ($criticalCount > 0) {
            return 'Critical';
        }

        if ($highCount > 0) {
            return 'Vulnerable';
        }

        if ($warningCount > 0) {
            return 'Warnings';
        }

        return 'Secure';
    }

    /**
     * @param \Illuminate\Support\Collection<int, \App\Models\SecurityThreatLog> $threatLogs
     * @return list<array{time: string, count: int}>
     */
    private function buildHourlyAttackVolume($threatLogs, Carbon $windowStart): array
    {
        $countByHour = $threatLogs
            ->filter(fn (SecurityThreatLog $log): bool => $log->detected_at !== null)
            ->groupBy(
                fn (SecurityThreatLog $log): string => $log->detected_at
                    ->copy()
                    ->startOfHour()
                    ->format('Y-m-d H:00')
            )
            ->map(fn ($logs): int => $logs->count());

        $startHour = $windowStart->copy()->startOfHour();

        return collect(range(0, 23))
            ->map(function (int $offset) use ($countByHour, $startHour): array {
                $hour = $startHour->copy()->addHours($offset);
                $key = $hour->format('Y-m-d H:00');

                return [
                    'time' => $hour->format('H:00'),
                    'count' => (int) ($countByHour[$key] ?? 0),
                ];
            })
            ->all();
    }

    /**
     * @param \Illuminate\Support\Collection<int, \App\Models\SecurityThreatLog> $threatLogs
     * @return list<array{path: string, count: int, percentage: float}>
     */
    private function buildTopTargetedPaths($threatLogs): array
    {
        $total = max(1, $threatLogs->count());

        return $threatLogs
            ->groupBy(function (SecurityThreatLog $log): string {
                $path = trim((string) ($log->path_targeted ?? ''));

                return $path !== '' ? $path : '/';
            })
            ->map(fn ($logs, string $path): array => [
                'path' => $path,
                'count' => $logs->count(),
                'percentage' => round(($logs->count() / $total) * 100, 1),
            ])
            ->sortByDesc('count')
            ->take(5)
            ->values()
            ->all();
    }

    /**
     * @param \Illuminate\Support\Collection<int, \App\Models\SecurityThreatLog> $threatLogs
     * @return list<array{country: string, count: int, percentage: float}>
     */
    private function buildTopOriginCountries($threatLogs): array
    {
        $total = max(1, $threatLogs->count());

        return $threatLogs
            ->groupBy(function (SecurityThreatLog $log): string {
                $country = trim((string) ($log->country ?? ''));

                return $country !== '' ? $country : 'Unknown';
            })
            ->map(fn ($logs, string $country): array => [
                'country' => $country,
                'count' => $logs->count(),
                'percentage' => round(($logs->count() / $total) * 100, 1),
            ])
            ->sortByDesc('count')
            ->take(5)
            ->values()
            ->all();
    }

    /**
     * @param \Illuminate\Support\Collection<int, \App\Models\MonitoredDomain> $domainModels
     * @return list<array{
     *     id: string,
     *     domain_id: int,
     *     domain: string,
     *     ip_address: string,
     *     notes: string|null,
     *     created_on: string|null,
     *     created_on_formatted: string
     * }>
     */
    private function loadActiveAccessRules($domainModels, CloudflareIpBlockService $cloudflareIpBlockService): array
    {
        return $domainModels
            ->filter(
                fn (MonitoredDomain $domain): bool => $domain->is_owned
                    && filled($domain->cloudflare_zone_id)
            )
            ->flatMap(function (MonitoredDomain $domain) use ($cloudflareIpBlockService) {
                $zoneId = trim((string) $domain->cloudflare_zone_id);
                $result = $cloudflareIpBlockService->listAccessRules($zoneId);

                if (!$result['success']) {
                    Log::warning("Cloudflare access rule lookup failed for {$domain->domain}: {$result['message']}");

                    return [];
                }

                return collect($result['rules'])->map(function (array $rule) use ($domain): array {
                    $createdOn = $rule['created_on'];

                    return [
                        'id' => $rule['id'],
                        'domain_id' => $domain->id,
                        'domain' => $domain->domain,
                        'ip_address' => $rule['ip_address'],
                        'notes' => $rule['notes'],
                        'created_on' => $createdOn,
                        'created_on_formatted' => $createdOn !== null
                            ? \Illuminate\Support\Carbon::parse($createdOn)->format('Y-m-d H:i:s T')
                            : 'Unknown',
                    ];
                });
            })
            ->sortByDesc(fn (array $rule): string => (string) ($rule['created_on'] ?? ''))
            ->values()
            ->all();
    }
}
