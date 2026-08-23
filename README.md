# Security & DNS Manager Engineering Handbook

Internal handbook updated from the current codebase state on **August 22, 2026**.

Scope analyzed:

- `app/Http`
- `app/Console`
- `app/Services`
- `database/migrations`
- `routes`

Supporting files referenced where necessary to explain actual runtime behavior:

- `app/Models`
- `app/Jobs/ScanGmailJob.php`
- `app/Notifications/SecurityAlertNotification.php`
- `bootstrap/app.php`
- `app/Providers/AppServiceProvider.php`

## 1. Architecture Overview

### 1.1 System Summary

This application is a centralized **security control plane** built on Laravel, Inertia.js, and React. It has two major operating domains:

1. **Messaging protection**
   - Scans Gmail messages and manual email payloads.
   - Analyzes SMS content.
   - Stores verdicts, risk scores, quarantine state, and reasoning.

2. **DNS / web / threat telemetry management**
   - Monitors DNS posture and web security state for registered domains.
   - Pulls firewall telemetry from Cloudflare for owned domains.
   - Accepts push telemetry from external middleware-enabled applications.
   - Maintains a central blocked-IP registry and notification pipeline.

The app is not itself an inline traffic filter. It is a **management plane** that stores telemetry, computes detections, exposes dashboards, and publishes block decisions for other systems to enforce.

### 1.2 Laravel Bootstrap and Runtime Shell

The runtime shell is defined by two files:

- `bootstrap/app.php`
  - Registers web routes from `routes/web.php`.
  - Registers API routes from `routes/api.php`.
  - Registers console schedule/commands from `routes/console.php`.
  - Exposes the Laravel health endpoint at `/up`.
  - Appends `HandleInertiaRequests` and Laravel's preload-header middleware to the web stack.
  - Aliases the `admin` middleware name to `App\Http\Middleware\EnsureUserIsAdmin`.
  - Trusts all proxies.

- `app/Providers/AppServiceProvider.php`
  - Forces HTTPS in production by calling `URL::forceScheme('https')`.

### 1.3 The Three Tiers

| Tier | Purpose | Source of Truth | Ingress Method | Main Storage | Enforcement Path |
| --- | --- | --- | --- | --- | --- |
| Tier 1: Universal DNS/SSL Audits | Passive posture scanning for DNS, SSL, and security headers | DNS records and live HTTP/SSL responses | Manual dashboard actions and scheduled DNS scans | `monitored_domains`, `dns_security_logs`, `web_security_scans` | Dashboard and alerting only |
| Tier 2: Cloudflare PULL Threat Sync | Pull firewall event telemetry from Cloudflare-owned zones | Cloudflare GraphQL firewall events | Scheduled sync via `app:sync-threats` | `security_threat_logs` | Cloudflare edge rules via `CloudflareIpBlockService` |
| Tier 3: App Middleware PUSH Telemetry & Auto-Ban | Accept threat events directly from client apps and auto-ban attackers | Client apps using bearer token auth | `POST /api/v1/telemetry/threats` | `security_threat_logs`, `blocked_ips` | Client apps pull blocked IPs from `GET /api/v1/telemetry/blocked-ips`; central app also records global bans |

### 1.4 Request / Data Lifecycle

#### Tier 1 lifecycle: DNS + web audit

1. An admin creates a monitored domain from `DnsSecurityController@store`.
2. The controller writes a row into `monitored_domains`.
3. It immediately runs:
   - `DnsScannerService::scan()` for DNS posture.
   - `UniversalSecurityScannerService::scan()` for HTTP/SSL/header posture.
4. Those services persist:
   - `dns_security_logs`
   - `web_security_scans`
   - updated `monitored_domains.last_checked_at`
   - updated `monitored_domains.ssl_certificate_info`
5. `DnsSecurityController@index` later renders those logs and latest scan data into the Inertia dashboard.

#### Tier 2 lifecycle: Cloudflare pull sync

1. A scheduled command runs `php artisan app:sync-threats`.
2. `SyncThreatsCommand` calls `CloudflareThreatService::syncOwnedDomains()`.
3. For each active owned domain:
   - if the domain is Cloudflare-backed, the service calls Cloudflare GraphQL for recent firewall events.
   - if the domain is middleware-backed, the same service aggregates locally ingested Tier 3 events.
4. New event rows are upserted into `security_threat_logs`.
5. Attack-spike alert logic can dispatch `SecurityAlertNotification`.
6. `threats_last_synced` is written to cache for dashboard freshness and Tier 3 aggregation windows.

#### Tier 3 lifecycle: client app push telemetry and central auto-ban

1. A client application sends a bearer token to `POST /api/v1/telemetry/threats`.
2. `VerifyAppSecretToken` resolves the token to an active `monitored_domains` row and attaches it to the request as `telemetryDomain`.
3. `TelemetryController@storeThreats` validates the JSON payload.
4. `AppThreatService::ingestThreatEvents()`:
   - upserts each event into `security_threat_logs`
   - increments a cache-based per-IP, per-domain counter for a 60-second window
   - compares the count against `monitored_domains.auto_ban_threshold`
   - writes a global row to `blocked_ips` when the threshold is exceeded
   - dispatches an `auto_ban` security alert
5. Client applications can later call `GET /api/v1/telemetry/blocked-ips` with the same bearer token.
6. `Api\BlockedIpController@index` returns a combined list of:
   - global bans (`is_global = true`)
   - domain-specific bans for that domain

#### Tier 3 protected-application integration guide

The in-app **Tier 3 Integration Guide** is the canonical copy/paste setup guide. Open DNS Security, select an Application Middleware (Tier 3) domain, choose **View Integration**, and then **Open Tier 3 Integration Guide**. Its generated examples include that domain's current bearer token.

Setup sequence:

1. Create or select an active `app_middleware` monitored domain and securely copy its application-secret token.
2. Add `SECURITY_MANAGER_URL`, `SECURITY_MANAGER_TOKEN`, and `SECURITY_MANAGER_DOMAIN` to the protected application's environment. Never commit the token.
3. Add the guide's `SecurityTelemetryClient`; it posts events and polls the central block list with the bearer token.
4. Add and register `SecurityTelemetryMiddleware` in the protected application's web middleware pipeline.
5. Optionally add the `Illuminate\Auth\Events\Failed` listener when the protected application has authentication.
6. Run the safe development test below, then confirm the enriched row in the central Threat Overview.

The sample middleware polls `GET /api/v1/telemetry/blocked-ips`, caches the returned list for five minutes, and rejects a matching client IP locally with HTTP 403. The API returns global blocks plus blocks scoped to the authenticated domain. Consequently, a newly added block can take up to the client's cache TTL to become visible. This polling and enforcement behavior has not changed.

The existing three-argument client call remains valid:

```php
$telemetryClient->reportThreat(
    $request->ip(),
    '/admin',
    (string) $request->userAgent(),
);
```

The client adds `timestamp` automatically and posts the established payload envelope:

```json
{
  "threats": [
    {
      "attacker_ip": "192.0.2.10",
      "targeted_path": "/admin",
      "user_agent": "Example Client/1.0",
      "timestamp": "2026-08-22T12:00:00+00:00"
    }
  ]
}
```

`event_type`, `severity`, `reason`, and `metadata` are optional additions. Existing integrations using the original three method arguments and base payload continue to work without changes. Historical records remain nullable and are shown as **Generic Threat / Unclassified**; no classification is invented for them.

```php
$telemetryClient->reportThreat(
    attackerIp: $request->ip(),
    targetedPath: '/login',
    userAgent: (string) $request->userAgent(),
    eventType: 'failed_login',
    severity: 'medium',
    reason: 'Authentication failed',
    metadata: ['route_name' => 'login'],
);
```

Field semantics are deliberately separate:

| Field | Meaning | Example |
| --- | --- | --- |
| `event_type` | **WHAT** happened | `failed_login` |
| `severity` | **HOW serious** the reported event is | `medium` |
| `reason` | **WHY** the application reported it | `Invalid credentials` |
| `action_taken` | **WHAT the central system did** | `log` |

Protected applications do not set `action_taken` through this API. Tier 3 ingestion continues to store `action_taken = log`; descriptive severity does not alter blocking or auto-ban decisions.

Allowed severities are `info`, `low`, `medium`, `high`, and `critical`. Suggested classifications are conservative:

| Signal | `event_type` | Suggested severity | Reason example |
| --- | --- | --- | --- |
| `.env` request | `environment_file_probe` | `high` | Attempt to access environment configuration file |
| `wp-admin` request | `wordpress_admin_probe` | `medium` | Probe for WordPress administrative endpoint |
| `phpMyAdmin` request | `phpmyadmin_probe` | `medium` | Probe for phpMyAdmin endpoint |
| Failed authentication | `failed_login` | `medium` | Authentication failed |
| Repeated failures already classified by the protected app | `brute_force` | `high` | Repeated login failures |
| Other suspicious request | `suspicious_request` | `low` or `medium` | Matched application security rule |
| Local development check | `test_probe` | `low` | Tier 3 telemetry development test |

The manager does not infer `brute_force` from severity or introduce a new blocking policy. A protected app may report that type only when its own established detection has made that classification.

For Laravel applications with authentication, the optional listener can consume `Illuminate\Auth\Events\Failed`:

```php
public function handle(\Illuminate\Auth\Events\Failed $event): void
{
    $request = request();

    rescue(fn () => $this->telemetryClient->reportThreat(
        attackerIp: (string) $request->ip(),
        targetedPath: '/login',
        userAgent: (string) $request->userAgent(),
        eventType: 'failed_login',
        severity: 'medium',
        reason: 'Authentication failed',
    ), report: false);

    // Never read or transmit $event->credentials; it can contain the password.
}
```

Applications without authentication do not need this listener. Laravel 12 discovers listeners placed under `app/Listeners` by default; applications with discovery disabled must register the listener through their normal event provider.

Metadata is only for small, sanitized security context such as `matched_pattern`, `http_method`, `route_name`, `status_code`, or `attempt_count`. Never send passwords or attempted passwords, Authorization headers, cookies, session IDs, OAuth tokens, API tokens/secrets, payment-card details, private keys, complete request bodies, or `.env` contents. Sensitive key names are rejected, and request input is never copied automatically into metadata.

Ingestion limits the full JSON request to 512 KB and each request to 100 events. `event_type` is lowercase snake_case up to 100 characters, `reason` is at most 2,000 characters, and metadata is a JSON object/array limited to 16 KB encoded, six levels of nesting, and 100 values. Existing path and user-agent limits remain 2,048 and 10,000 characters. Invalid inputs return HTTP 422.

Safe development test (use only a development/staging manager and token):

```bash
TEST_TIMESTAMP="$(date -Iseconds)"

curl --request POST 'https://your-security-manager-domain.com/api/v1/telemetry/threats' \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_APP_SECRET_TOKEN' \
  --data "{\"threats\":[{\"attacker_ip\":\"192.0.2.10\",\"targeted_path\":\"/test-middleware\",\"user_agent\":\"Tier3-Development-Test/1.0\",\"timestamp\":\"${TEST_TIMESTAMP}\",\"event_type\":\"test_probe\",\"severity\":\"low\",\"reason\":\"Tier 3 telemetry development test\",\"metadata\":{\"test_run\":true}}]}"
```

Threat Overview should show **Test Probe**, **Low**, source IP `192.0.2.10`, target `/test-middleware`, the development-test reason, and **Action Taken: LOG**. The sample middleware also recognizes `/test-middleware` only under `APP_ENV=local`; do not add or expose a dedicated production test endpoint.

Troubleshooting:

- HTTP 401: verify the bearer token is present, matches the selected monitored domain, and that the domain is active.
- Endpoint unreachable: verify `SECURITY_MANAGER_URL`, TLS/DNS reachability, and outbound access from the protected app.
- Blocked IP not enforced immediately: allow for the sample client's five-minute block-list cache.
- Event shown as Unclassified: the sender used the backward-compatible legacy payload without enrichment.
- HTTP 422 for severity: use only the five canonical lowercase values.
- HTTP 422 for metadata or other fields: check the documented size/depth/count limits and remove prohibited sensitive keys.

#### Important enforcement note

This repository does **not** contain an inline middleware that automatically reads `blocked_ips` and returns `403` to attacker traffic. The central application is a control plane.

Current blocked-IP behavior is:

- `AppThreatService` creates canonical ban rows in `blocked_ips`.
- `Api\BlockedIpController@index` exposes those rows to external apps.
- `CloudflareIpBlockService` manages Cloudflare edge rules for Tier 2 admin actions.
- `CloudflareThreatService::processMiddlewareTelemetry()` caches telemetry summaries and a derived blocked-IP list for reporting, not for in-app request rejection.

### 1.5 Secondary Messaging Pipeline

The same codebase also runs a Gmail and manual-message inspection pipeline:

1. `scan:all` dispatches `ScanGmailJob` for users with Gmail tokens and `auto_quarantine = true`.
2. `GmailService` fetches the latest inbox messages.
3. `LinkExtractionService` extracts links and resolves URL shorteners.
4. `EmailScannerService` executes a layered analysis funnel:
   - whitelist
   - heuristics
   - VirusTotal
   - Gemini AI reasoning
   - optional financial PDF extraction
5. High-risk messages can trigger:
   - origin tracing via `EmailOriginService`
   - Gmail auto-quarantine
   - threat alert email via `ThreatAlertMail`

## 2. Route and Entry-Point Inventory

### 2.1 `routes/web.php`

#### Root route

- `GET /`
  - Redirects to `/login`.

#### `auth + verified` routes

| Route | Controller action | Purpose |
| --- | --- | --- |
| `GET /dashboard` | `DashboardController@index` | Main user dashboard for email/SMS alerts and stats |
| `POST /auth/disconnect` | `DashboardController@disconnect` | Disconnect Google OAuth tokens |
| `POST /scan/mark-safe/{id}/{source}` | `DashboardController@markSafe` | Manual override for scanned email or SMS |
| `DELETE /scan/delete/{id}/{source}` | `DashboardController@deleteRecord` | Delete an email or SMS record |
| `GET /sms-scanner` | `SmsController@index` | SMS scanner UI |
| `POST /sms-analyze` | `SmsController@analyze` | AI scan of an SMS message |
| `GET /dns-security` | `DnsSecurityController@index` | DNS and threat telemetry dashboard |
| `POST /dns-security` | `DnsSecurityController@store` | Create a monitored domain and kick off initial scans |
| `POST /dns-security/alert-settings` | `DnsSecurityController@updateAlertSettings` | Save notification channel settings |
| `POST /dns-security/block-ip` | `DnsSecurityController@blockIp` | Push a block rule to Cloudflare |
| `POST /dns-security/unblock-ip` | `DnsSecurityController@unblockIp` | Remove a Cloudflare access rule |
| `PATCH /dns-security/{domain}` | `DnsSecurityController@update` | Save domain ownership / zone / auto-ban settings |
| `GET /dns-security/ip-lookup/{ip}` | `DnsSecurityController@lookupIp` | IP intelligence lookup for the DNS dashboard |
| `POST /dns-security/{domain}/scan` | `DnsSecurityController@scan` | Manually run DNS + web scan for one domain |
| `DELETE /dns-security/{domain}` | `DnsSecurityController@destroy` | Delete a monitored domain |

#### `auth + verified + admin` routes

| Route | Controller action | Purpose |
| --- | --- | --- |
| `GET /admin/dashboard` | `AdminDashboardController@index` | Admin console |
| `GET /admin/blocked-ips` | `AdminBlockedIpController@index` | Blocked-IP management page |
| `DELETE /admin/blocked-ips/{blockedIp}` | `AdminBlockedIpController@destroy` | Remove a ban row and audit it |
| `GET /admin/threats/export` | `AdminDashboardController@exportGlobalThreats` | Export threat feed as JSON |
| `GET /admin/ip-intelligence/{ip}` | `AdminDashboardController@getIpIntelligence` | Admin IP intelligence lookup |
| `POST /admin/domains/{domain}/toggle-status` | `AdminDashboardController@toggleDomainStatus` | Enable or disable Tier 3 domain ingestion |
| `POST /admin/domains/{domain}/rotate-token` | `AdminDashboardController@rotateAppToken` | Rotate middleware bearer token |
| `POST /admin/users` | `AdminDashboardController@storeUser` | Provision a user in the admin's org |
| `PUT /admin/users/{user}` | `AdminDashboardController@updateUser` | Update user profile / role / password |
| `POST /admin/queue/retry` | `AdminDashboardController@retryAllFailedJobs` | Retry all failed queue jobs |

#### `auth` routes

| Route | Controller/action | Purpose |
| --- | --- | --- |
| `POST /api/scan-email` | `EmailScanController@store` | Manual email scanning endpoint behind session auth |
| `GET /profile` | `ProfileController@edit` | Profile UI |
| `PATCH /profile` | `ProfileController@update` | Save name/email changes |
| `DELETE /profile` | `ProfileController@destroy` | Delete current account |
| `GET /auth/redirect` | `AuthController@redirect` | Start Google OAuth |
| `GET /auth/callback` | `AuthController@callback` | Complete Google OAuth |
| `GET /domains` | `DomainController@index` | Whitelisted-domain admin page |
| `POST /domains` | `DomainController@store` | Add whitelist domain |
| `PATCH /domains/{domain}` | `DomainController@update` | Toggle whitelist domain active state |
| `DELETE /domains/{domain}` | `DomainController@destroy` | Delete whitelist domain |
| `POST /settings/toggle-quarantine` | route closure | Toggle `users.auto_quarantine` |

### 2.2 `routes/api.php`

All API telemetry routes are grouped under `/api/v1/telemetry` and protected by `VerifyAppSecretToken`.

| Route | Controller action | Purpose |
| --- | --- | --- |
| `POST /api/v1/telemetry/threats` | `Api\TelemetryController@storeThreats` | Accept Tier 3 threat events |
| `GET /api/v1/telemetry/blocked-ips` | `Api\BlockedIpController@index` | Return merged global + domain block list |

### 2.3 `routes/auth.php`

Standard Laravel Breeze/Inertia authentication surface:

- Guest routes
  - register
  - login
  - forgot password
  - reset password
- Authenticated routes
  - verify email
  - resend verification email
  - confirm password
  - change password
  - logout

Middleware semantics:

- `guest` keeps authenticated users out of login/register flows.
- `auth` requires a session-authenticated user.
- `signed` protects email verification links.
- `throttle:6,1` limits verification-related endpoints.

### 2.4 `routes/console.php`

Scheduled tasks:

| Schedule | Command | Purpose |
| --- | --- | --- |
| every minute, without overlap | `scan:all` | Dispatch Gmail scan jobs |
| twice daily, without overlap | `app:scan-dns` | Run Tier 1 DNS + web scans |
| daily | `emails:cleanup` | Retention cleanup for scanned emails |
| every ten minutes | `app:sync-threats` | Tier 2 + Tier 3 threat sync/aggregation |

## 3. Core Controllers and Actions

### 3.1 `app/Http/Controllers/Controller.php`

Base abstract controller with no custom logic.

### 3.2 `AdminBlockedIpController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index()` | Loads all blocked IP rows newest-first, eager-loads each related `monitoredDomain`, maps them into Inertia-safe arrays, renders `Admin/BlockedIpsIndex`. | Reads `blocked_ips`; reads related `monitored_domains`. |
| `destroy(Request $request, BlockedIp $blockedIp)` | Loads related domain, captures audit metadata, deletes the ban row, writes an audit log with action `unblocked_ip`, redirects back to the blocked-IP index with a success flash. | Deletes one `blocked_ips` row; inserts one `system_audit_logs` row. |

### 3.3 `AdminDashboardController`

Important note: all public methods still perform manual `abort(403)` checks on `Auth::user()->role === 'admin'` even though admin routes are now also protected by `EnsureUserIsAdmin`.

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index(Request $request)` | Builds the admin dashboard view model. Loads all high-threat emails, organization users, optional date-range reporting metrics, whitelisted domains, queue depth, failed-job samples, top targeted paths, top attacker IPs, Tier 3 domains with visible tokens, and the latest audit trail. | Reads `scanned_emails`, `scanned_sms`, `users`, `whitelisted_domains`, `jobs`, configured failed-jobs table, `security_threat_logs`, `monitored_domains`, `system_audit_logs`. |
| `exportGlobalThreats(Request $request)` | Returns the latest 10,000 threat log rows as JSON and sets a download-oriented content disposition header. | Reads `security_threat_logs` and related `monitored_domains`. |
| `getIpIntelligence(string $ip, IpIntelligenceService $service)` | Validates that the path parameter is a real IP, calls the IP intelligence service, and normalizes success/failure responses for the frontend. | No direct DB writes; indirect cache and external HTTP happen inside the service. |
| `rotateAppToken(MonitoredDomain $domain)` | Rejects non-Tier-3 domains, generates a new random 64-character `app_secret_token`, writes an audit log, and flashes success. | Updates `monitored_domains`; inserts `system_audit_logs`. |
| `toggleDomainStatus(MonitoredDomain $domain)` | Rejects non-Tier-3 domains, flips `is_active`, saves the domain, records an audit event whose action reflects enable vs disable. | Updates `monitored_domains`; inserts `system_audit_logs`. |
| `retryAllFailedJobs(Request $request)` | Verifies failed-job storage exists, calls `Artisan::call('queue:retry', ['id' => 'all'])`, writes an audit log, and returns a flash response. | Reads configured failed-jobs table existence; inserts `system_audit_logs`. |
| `storeUser(Request $request)` | Validates name and email, creates a user with default password `password`, assigns the admin's `organization_id`, and forces role `user`. | Inserts `users`. |
| `updateUser(Request $request, User $user)` | Ensures the target user belongs to the admin's organization, validates name/email/role/password, hashes password if present, updates the user. | Updates `users`. |

### 3.4 `AuthController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `redirect()` | Starts a stateless Google Socialite flow, requests configured scopes, requests offline access and consent, then redirects the browser to Google. | No DB changes. |
| `callback()` | Resolves the logged-in user, exchanges the Google callback for user tokens, updates encrypted Google access/refresh token columns and expiry, then redirects to the dashboard. | Updates `users.google_access_token`, `users.google_refresh_token`, `users.google_token_expires_at`, and clears legacy `users.token`. |

### 3.5 `DashboardController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index(Request $request)` | Loads current user, counts scanned emails/SMS and threat counts, builds a combined feed from the latest 50 emails and latest 50 SMS items, applies `all/threats/email/sms` filtering, sorts by `created_at`, and renders the user dashboard. | Reads `scanned_emails`; reads `scanned_sms`. |
| `disconnect()` | Clears all Google token columns from the current user and redirects with success. | Updates `users`. |
| `markSafe($id, $source)` | Normalizes the prefixed alert ID, finds the row owned by the current user, then forces the record back to a safe state. Email path resets verdict, category, reasoning, and analysis chain; SMS path resets threat and risk/severity. | Updates either `scanned_emails` or `scanned_sms`. |
| `deleteRecord($id, $source)` | Normalizes the prefixed alert ID, finds the user-owned record, deletes it, and flashes success. Because the models use `SoftDeletes`, this is a soft delete for email and SMS rows. | Soft-deletes either `scanned_emails` or `scanned_sms`. |

### 3.6 `DnsSecurityController`

This is the main Tier 1 / Tier 2 / Tier 3 operator controller.

#### Public methods

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index(CloudflareIpBlockService $service)` | Builds the DNS Security Manager dashboard. Loads last 24 hours of owned-domain threat logs, aggregates them by domain, loads all monitored domains with issue counts and latest web scan, resolves Cloudflare access rules for owned domains with zone IDs, formats recent DNS logs, formats recent threat logs, builds threat analytics, injects cached last-sync time, and exposes the current user's alert settings. | Reads `security_threat_logs`, `monitored_domains`, `dns_security_logs`, `web_security_scans`, current `users` alert fields; indirect Cloudflare API reads via `CloudflareIpBlockService::listAccessRules()`. |
| `store(Request $request, DnsScannerService $scanner, UniversalSecurityScannerService $webScanner)` | Normalizes input, validates domain, infrastructure type, and optional Cloudflare zone ID, determines `is_owned`, inserts a monitored-domain row, then immediately runs DNS and web scans. Success responses include scan counts and an extra Tier 3 integration note for middleware domains. | Inserts `monitored_domains`; writes `dns_security_logs`, `web_security_scans`, and updates `monitored_domains.last_checked_at` through service calls. |
| `destroy(MonitoredDomain $domain)` | Deletes a monitored domain and flashes success. | Deletes one `monitored_domains` row; cascades related logs/scans/threats/blocked IPs depending on FK behavior. |
| `scan(MonitoredDomain $domain, DnsScannerService $scanner, UniversalSecurityScannerService $webScanner)` | Manually re-runs the same DNS and web scan pipeline as `store()`. | Inserts new `dns_security_logs` and `web_security_scans`; updates domain status metadata. |
| `update(Request $request, MonitoredDomain $domain)` | Validates and saves infrastructure-specific settings. For Tier 3 domains it forces `is_owned=true`, clears the zone ID, and saves `auto_ban_threshold`. For universal domains it forces passive mode and saves `auto_ban_threshold`. For Cloudflare domains it validates `is_owned` and zone ID pairing, then saves zone ID and threshold. | Updates `monitored_domains`. |
| `updateAlertSettings(Request $request)` | Validates notification channel toggles plus required webhook/bot fields when enabled, then writes alert preferences into the authenticated user record. | Updates `users`. |
| `blockIp(Request $request, CloudflareIpBlockService $service)` | Validates `domain_id` and `ip_address`, ensures the target domain is owned and has a zone ID, calls Cloudflare to create a block rule, logs the event to Laravel logs, then flashes success. | Reads `monitored_domains`; external Cloudflare write via API. |
| `unblockIp(Request $request, CloudflareIpBlockService $service)` | Validates `domain_id` and `rule_id`, ensures the target domain is owned and has a zone ID, calls Cloudflare to delete the access rule, logs the event, then flashes success or error. | Reads `monitored_domains`; external Cloudflare delete via API. |
| `lookupIp(string $ip, IpIntelligenceService $service)` | Validates the IP string and returns normalized IP intelligence service results. | No direct DB writes; service uses cache + external HTTP. |

#### Private helpers

| Helper | Purpose |
| --- | --- |
| `normalizeDomainInput()` | Strips scheme, leading `www.`, trailing slash noise, and lowercases domain input. |
| `isValidDomain()` | Uses `FILTER_VALIDATE_DOMAIN` plus `.` presence to confirm a host-like domain. |
| `determineOverallHealthStatus()` | Converts unresolved issue counts into `Critical`, `Vulnerable`, `Warnings`, or `Secure`. |
| `buildHourlyAttackVolume()` | Buckets threat log rows into a 24-hour `H:00` series for charting. |
| `buildTopTargetedPaths()` | Aggregates top targeted URL paths and their percentages. |
| `buildTopOriginCountries()` | Aggregates origin-country counts and percentages. |
| `loadActiveAccessRules()` | For owned domains with zone IDs, fetches Cloudflare block rules, formats them, and sorts them newest-first. |

### 3.7 `DomainController`

This controller manages the **whitelist**, not monitored domains.

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index()` | Loads all whitelisted domains newest-first and renders the admin domain manager page. | Reads `whitelisted_domains`. |
| `store(Request $request)` | Validates domain and description, normalizes the domain by stripping scheme/host noise, inserts a whitelist row, clears the `trusted_domains` cache key, and flashes success. | Inserts `whitelisted_domains`; clears cache. |
| `update(Request $request, WhitelistedDomain $domain)` | Validates `is_active`, updates the row, clears the whitelist cache, and flashes success. | Updates `whitelisted_domains`; clears cache. |
| `destroy(WhitelistedDomain $domain)` | Deletes the whitelist row, clears cache, flashes success. | Deletes `whitelisted_domains`; clears cache. |

### 3.8 `EmailScanController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `store(Request $request, EmailScannerService $scanner)` | Validates a batch of incoming email payloads, loops through them, runs `scanAndStore()` for each, formats each result, and returns a JSON `results` array. | Inserts or returns existing `scanned_emails`; may read/write `scanned_urls` through VirusTotal helper. |

### 3.9 `ProfileController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `edit(Request $request)` | Renders profile UI and tells the frontend whether email verification applies. | No writes. |
| `update(ProfileUpdateRequest $request)` | Fills the current user with validated name/email changes, clears `email_verified_at` if email changed, saves user, redirects back to profile. | Updates `users`. |
| `destroy(Request $request)` | Validates current password, logs the user out, deletes the user, invalidates session, rotates CSRF token, redirects to `/`. | Deletes `users`; invalidates session. |

### 3.10 `SmsController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index()` | Renders the SMS scanner UI. | No DB access. |
| `analyze(Request $request)` | Validates sender/message, ensures Gemini API key exists, constructs a smishing prompt, retries the AI call up to 3 times, parses JSON output, stores a `scanned_sms` row, and returns the analysis JSON. On failure it logs and returns error JSON. | Inserts `scanned_sms`; external Gemini HTTP call. |

### 3.11 `Api\BlockedIpController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `index(Request $request)` | Reads the `telemetryDomain` request attribute from `VerifyAppSecretToken`, queries `blocked_ips` for all global entries or entries tied to that domain, returns a unique sorted JSON list of IP strings. | Reads `blocked_ips`. |

Private helper:

- `telemetryDomain(Request $request)`
  - Pulls the attached domain from request attributes.
  - Throws `401 Unauthorized` if the middleware did not attach a domain.

### 3.12 `Api\TelemetryController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `storeThreats(Request $request, AppThreatService $service)` | Resolves the bearer-token-authenticated domain; validates 1–100 posted events and their required base fields plus optional `event_type`, canonical `severity`, `reason`, and bounded sanitized `metadata`; hands the events to `AppThreatService`; and returns a `202 Accepted` JSON summary. | Upserts `security_threat_logs`; may insert `blocked_ips` through the unchanged service policy. |

Private helpers:

| Helper | Purpose |
| --- | --- |
| `validatedThreatEvents()` | Accepts either a top-level list or a `threats/events` wrapper, then validates `attacker_ip`, `targeted_path`, `user_agent`, and `timestamp`. |
| `telemetryDomain()` | Returns the token-authenticated domain or aborts with `401`. |

### 3.13 Authentication Controllers (`app/Http/Controllers/Auth`)

#### `AuthenticatedSessionController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `create()` | Renders login UI and exposes password-reset availability. | Reads route availability and session flash only. |
| `store(LoginRequest $request)` | Calls the custom login request's authentication logic, regenerates the session, redirects to intended destination. | Reads `users` via `Auth::attempt`; updates session state. |
| `destroy(Request $request)` | Logs out, invalidates session, regenerates CSRF token, redirects to `/`. | Session store only. |

#### `ConfirmablePasswordController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `show()` | Renders password confirmation UI. | No writes. |
| `store(Request $request)` | Validates the current user's password using `Auth::guard('web')->validate`, stores `auth.password_confirmed_at` in session, redirects to intended route. | Session only. |

#### `EmailVerificationNotificationController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `store(Request $request)` | If email is already verified, redirects to dashboard. Otherwise sends verification mail and flashes `verification-link-sent`. | No direct DB write. |

#### `EmailVerificationPromptController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `__invoke(Request $request)` | Redirects verified users to dashboard; otherwise renders the verify-email page. | No writes. |

#### `NewPasswordController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `create(Request $request)` | Renders the reset-password UI with email and token from the request. | No writes. |
| `store(Request $request)` | Validates token/email/password confirmation, uses Laravel's password broker to reset the user password, rotates the remember token, fires `PasswordReset`, and redirects to login or throws validation errors. | Updates `users.password` and `users.remember_token`; uses `password_reset_tokens`. |

#### `PasswordController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `update(Request $request)` | Validates current password and new password confirmation, hashes the new password, updates the current user. | Updates `users.password`. |

#### `PasswordResetLinkController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `create()` | Renders forgot-password page. | No writes. |
| `store(Request $request)` | Validates email, asks Laravel password broker to send reset link, returns status or validation error. | Uses `password_reset_tokens` through Laravel internals. |

#### `RegisteredUserController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `create()` | Renders registration page. | No writes. |
| `store(Request $request)` | Validates user registration fields, creates a new user, fires `Registered`, logs the user in, redirects to dashboard. | Inserts `users`. |

#### `VerifyEmailController`

| Method | Exact logic | Database interaction |
| --- | --- | --- |
| `__invoke(EmailVerificationRequest $request)` | If already verified, redirects with `verified=1`; otherwise marks the email verified, fires `Verified`, redirects with `verified=1`. | Updates `users.email_verified_at`. |

## 4. Middleware and Security Enforcement

### 4.1 Middleware registration and route-level security

From `bootstrap/app.php`:

- Web stack appends:
  - `App\Http\Middleware\HandleInertiaRequests`
  - `Illuminate\Http\Middleware\AddLinkHeadersForPreloadedAssets`
- Middleware alias:
  - `admin` => `EnsureUserIsAdmin`
- Global trust proxy configuration is enabled for all proxies.

Route-level middleware used in this codebase:

- `auth`
- `verified`
- `guest`
- `signed`
- `throttle:6,1`
- `admin`
- `VerifyAppSecretToken` on telemetry APIs

### 4.2 `EnsureUserIsAdmin`

File: `app/Http/Middleware/EnsureUserIsAdmin.php`

| Method | Behavior |
| --- | --- |
| `handle(Request $request, Closure $next)` | Calls `abort_unless($request->user()?->isAdmin(), 403)`. If the current user is missing or not admin, the request ends with HTTP 403. Otherwise the request continues. |

This is the only custom middleware in the repo that directly returns a `403 Access Denied`.

### 4.3 `VerifyAppSecretToken`

File: `app/Http/Middleware/VerifyAppSecretToken.php`

| Method | Behavior |
| --- | --- |
| `handle(Request $request, Closure $next)` | Reads the bearer token, rejects missing tokens, looks up an active `MonitoredDomain` by `app_secret_token`, rejects invalid or inactive tokens, stores the resolved domain in `$request->attributes['telemetryDomain']`, then allows the request through. |
| `unauthorizedResponse(string $message)` | Returns JSON `{ "message": ... }` with HTTP 401. |

Important semantics:

- It returns **401**, not 403.
- It does **not** read the `blocked_ips` table.
- It does **not** cache blocked IPs.
- Its only job is authenticating Tier 3 middleware clients and attaching the domain context.

### 4.4 `HandleInertiaRequests`

File: `app/Http/Middleware/HandleInertiaRequests.php`

| Method | Behavior |
| --- | --- |
| `version(Request $request)` | Uses default Inertia asset versioning behavior. |
| `share(Request $request)` | Adds shared page props: authenticated user object and `flash.success` / `flash.error`. |

### 4.5 Form request validators

#### `LoginRequest`

| Method | Behavior |
| --- | --- |
| `authorize()` | Always returns `true`. |
| `rules()` | Requires `email` and `password`. |
| `authenticate()` | Enforces throttle, attempts login with optional remember flag, increments throttle on failure, clears throttle on success. |
| `ensureIsNotRateLimited()` | Throws validation error when 5 login attempts have been exceeded for the throttle key. |
| `throttleKey()` | Uses normalized email + source IP as the limiter key. |

HTTP security effect:

- Login lockouts return validation errors, not 403.
- Rate limiting behavior is effectively 5 attempts per email/IP tuple.

#### `ProfileUpdateRequest`

| Method | Behavior |
| --- | --- |
| `rules()` | Validates required name and unique email for the current user. |

### 4.6 Where blocked IPs are actually cached or enforced

There is no `SecurityTelemetryMiddleware` class in this repository.

Blocked-IP related logic exists in services:

| Location | What it does |
| --- | --- |
| `AppThreatService::handleAutoBan()` | Maintains `threat_count_{ip}_{domain}` cache entries for a 60-second rolling threshold window, then creates a `blocked_ips` row when the threshold is exceeded. |
| `CloudflareThreatService::processMiddlewareTelemetry()` | Caches `telemetry_blocked_ips:{domainId}` for 10 minutes and `middleware_threat_summary:{domainId}` for 1 hour for reporting purposes. |
| `Api\BlockedIpController@index` | Reads canonical data from `blocked_ips` and returns it to clients. |
| `DnsSecurityController@blockIp` / `unblockIp` | Pushes blocks to Cloudflare edge rules for Tier 2 operations. |

Operationally:

- Tier 3 client applications are expected to **poll the block list** and enforce it locally.
- Tier 2 domains can be protected at Cloudflare via admin-issued edge block rules.
- The central Laravel app does not perform attacker-request rejection using the `blocked_ips` table.

### 4.7 Security status code summary

| Code | Where it happens | Reason |
| --- | --- | --- |
| `401` | `VerifyAppSecretToken` | Missing, invalid, or inactive Tier 3 bearer token |
| `403` | `EnsureUserIsAdmin`; manual admin checks; `signed` middleware failures | User lacks admin role or link signature is invalid |
| `422` | Controller/form validation errors | Input is malformed or business preconditions fail |
| `429` | `LoginRequest` throttling; `SmsController` busy fallback | Rate limiting or temporary service pressure |

## 5. Console Commands and Scheduled Jobs

### 5.1 Schedule map

| Schedule | Command | Overlap policy | Effect |
| --- | --- | --- | --- |
| every minute | `scan:all` | `withoutOverlapping()` | Dispatch Gmail scan jobs for eligible users |
| twice daily | `app:scan-dns` | `withoutOverlapping()` | Tier 1 posture scans across active domains |
| daily | `emails:cleanup` | none | Retention cleanup for old email records |
| every ten minutes | `app:sync-threats` | none | Tier 2 Cloudflare sync and Tier 3 aggregation |

### 5.2 `CleanupOldEmails`

| Property / method | Behavior |
| --- | --- |
| signature | `emails:cleanup` |
| description | Deletes scanned emails older than 14 days for retention compliance |
| `handle()` | Calculates `now()->subDays(14)` and calls `ScannedEmail::where('created_at', '<', $cutoff)->delete()`. Because `ScannedEmail` uses `SoftDeletes`, this is a logical delete, not a physical purge. |

### 5.3 `ScanAllUsers`

| Property / method | Behavior |
| --- | --- |
| signature | `scan:all` |
| description | Dispatch scan jobs for all connected users |
| `handle()` | Selects users where `auto_quarantine = true` and at least one Google token exists, processes them in `chunkById(100)`, dispatches `ScanGmailJob` per user, prints a dispatch count, returns `SUCCESS`. |

Filtering constraints:

- User must have `auto_quarantine = true`.
- User must have either `google_access_token` or `google_refresh_token`.

### 5.4 `ScanDnsCommand`

| Property / method | Behavior |
| --- | --- |
| signature | `app:scan-dns` |
| description | Scan active monitored domains for DNS drift, email security misconfiguration, and web security health |
| `handle(DnsScannerService, UniversalSecurityScannerService)` | Loads all active monitored domains, prints a progress bar, runs both scanners for each domain, aggregates vulnerability counts by severity, reports failures per domain, and returns `SUCCESS`. |

Filtering constraints:

- Only `monitored_domains.is_active = true` are scanned.
- No further tier restriction: universal, Cloudflare, and middleware domains are all scanned if active.

### 5.5 `SyncThreatsCommand`

| Property / method | Behavior |
| --- | --- |
| signature | `app:sync-threats` |
| description | Process recent Tier 2 Cloudflare threats and Tier 3 middleware telemetry for owned domains |
| `handle(CloudflareThreatService)` | Calls `syncOwnedDomains()`, prints processed/synced/skipped/failed counts, stores `threats_last_synced` in cache, returns `SUCCESS`. |

Filtering constraints live inside `CloudflareThreatService`:

- Domain must be `is_active = true`.
- Domain must be `is_owned = true`.
- Cloudflare path requires a configured Cloudflare API token and a non-empty `cloudflare_zone_id`.
- Middleware path requires `infrastructure_type = 'app_middleware'`.

### 5.6 `TestEmailScanner`

| Property / method | Behavior |
| --- | --- |
| signature | `scanner:test {pdf_path} {--sender=wesleykjr13@gmail.com}` |
| description | Directly test email scanner with a local PDF attachment |
| `handle(EmailScannerService)` | Verifies file existence, builds a synthetic email payload with the PDF attached, reflectively calls the private `analyzeFinancialAttachments()` method for debugging, then runs the full email scanner and prints formatted JSON output. |

### 5.7 Supporting queued job: `ScanGmailJob`

Even though it lives outside `app/Console`, this job is part of the scheduled execution chain started by `scan:all`.

| Method | Behavior |
| --- | --- |
| `__construct(User $user)` | Stores the user payload. |
| `middleware()` | Applies queue `RateLimited('gemini-api')` middleware. |
| `handle(EmailScannerService, EmailOriginService, LinkExtractionService)` | Skips users with no tokens, fetches the latest 5 inbox emails, extracts links, scans and stores messages, optionally traces origin for `risk_score >= 90`, optionally auto-quarantines Gmail messages when `risk_score >= 90` and `auto_quarantine = true`, sends `ThreatAlertMail` to a hard-coded admin address on successful quarantine. |
| `buildAuthenticatedGmailService()` | Rebuilds an authenticated Google Gmail client, refreshing access tokens if expired. |
| `refreshGoogleAccessToken()` | Uses the stored refresh token to update encrypted Google access token columns. |

## 6. Services and Integration Logic

### 6.1 Threat-ingestion and infrastructure services

#### `AppThreatService`

| Method | Behavior |
| --- | --- |
| `__construct(SecurityAlertDispatcher)` | Injects the alert dispatcher. |
| `ingestThreatEvents(MonitoredDomain $domain, array $events)` | Iterates validated Tier 3 events, additively persists any supplied threat-detail fields, upserts each event with `action_taken = 'log'` and `threat_source = 'app_middleware'`, preserves existing enrichment when a legacy retry omits it, counts synced vs newly-created events, and calls the unchanged `handleAutoBan()` for each attacker IP. |
| `handleAutoBan(MonitoredDomain $domain, string $attackerIp)` | Maintains a 60-second cache counter per IP/domain, compares it with `auto_ban_threshold` (minimum 1), refuses to duplicate an existing blocked IP, writes a global `blocked_ips` row with reason `Auto-banned: exceeded threat threshold`, and dispatches an `auto_ban` alert. |

#### `CloudflareIpBlockService`

| Method | Behavior |
| --- | --- |
| `listAccessRules(string $zoneId)` | Uses the configured Cloudflare API token to request block-mode access rules for a zone, maps each rule into a simplified array, and normalizes failure messages. |
| `blockIp(string $zoneId, string $attackerIp)` | Creates a zone-scoped Cloudflare firewall access rule in `block` mode with a standard note string. |
| `deleteAccessRule(string $zoneId, string $ruleId)` | Deletes an existing Cloudflare access rule by ID. |
| `resolveCloudflareErrorMessage(array $payload)` | Collapses Cloudflare `errors[]` messages into a semicolon-delimited string. |
| `nullableString(mixed $value)` | Utility normalizer for optional string fields. |

External I/O:

- `https://api.cloudflare.com/client/v4/zones/{zone}/firewall/access_rules/rules`

#### `CloudflareThreatService`

| Method | Behavior |
| --- | --- |
| `__construct(SecurityAlertDispatcher)` | Injects alert dispatcher. |
| `syncOwnedDomains()` | Loads active owned domains and chooses processing path per domain: Cloudflare pull, middleware aggregation, or skip. Tracks processed/synced/failed/skipped counts and dispatches attack-spike alerts when needed. |
| `shouldProcessAsCloudflare(MonitoredDomain $domain)` | Treats a domain as Cloudflare-processable when `infrastructure_type = 'cloudflare'` or a zone ID exists. |
| `syncDomainThreats(MonitoredDomain $domain, string $zoneId, string $token)` | Requests the last two hours of Cloudflare firewall events via GraphQL and forwards them to `storeEvents()`. |
| `buildQuery()` | Returns the GraphQL query string for firewall events. |
| `storeEvents(MonitoredDomain $domain, Collection $events)` | Upserts Cloudflare firewall events into `security_threat_logs`, mapping IP, country, request path, action, source, and timestamp. |
| `processMiddlewareTelemetry(MonitoredDomain $domain)` | For Tier 3 domains, counts newly-created middleware events since the last sync window, computes top targeted paths and attacker IPs, derives a list of blocked IPs from rows whose `action_taken = 'block'`, stores summary caches, and returns new-event counts. |
| `resolveMiddlewareSyncStart()` | Uses cached `threats_last_synced` when present; otherwise falls back to `now() - 24 hours`. |
| `nullableString(mixed $value)` | Optional-string normalizer. |
| `dispatchAttackSpikeAlert(MonitoredDomain $domain, int $newEventsCount)` | If at least 10 new events arrived, sends an alert throttled by cache for 30 minutes; severity becomes `CRITICAL` at 25+ events. |

Caching used:

- `threats_last_synced`
- `telemetry_blocked_ips:{domainId}`
- `middleware_threat_summary:{domainId}`
- `alert_spike_{domainId}`

#### `DnsScannerService`

| Method | Behavior |
| --- | --- |
| `__construct(SecurityAlertDispatcher)` | Injects alert dispatcher. |
| `scan(MonitoredDomain $monitoredDomain)` | Performs A, MX, TXT, and DMARC lookups; evaluates A, MX, SPF, DMARC, and DKIM posture; writes new DNS logs; updates `last_checked_at`; dispatches DNS drift alerts; returns vulnerability counts by severity. |
| `lookupDnsRecords(string $hostname, int $dnsType)` | Performs DNS lookup with optional `pcntl_alarm` timeout protection and warning-to-exception conversion. |
| `evaluateAddressRecords(...)` | Compares live A records against expected baseline; writes `missing`, `mismatch`, or `secure` logs. |
| `evaluateMailExchangeRecords(...)` | Same pattern for MX records. |
| `evaluateSpfRecords(...)` | Validates presence, uniqueness, and enforcement quality of SPF records. |
| `evaluateDmarcRecords(...)` | Validates presence, uniqueness, policy tag existence, and enforcement level for DMARC. |
| `evaluateDkimRecords(...)` | Probes common selectors to determine whether DKIM records are discoverable. |
| `normalizeAddressRecords()` | Canonicalizes A-record values for comparison. |
| `normalizeMxRecords()` | Canonicalizes MX records including priority. |
| `extractTaggedValue()` | Reads `p=` or similar DMARC/SPF tags from TXT strings. |
| `resolveExpectedValue()` | Uses the latest stored expected value or falls back to the current observed value. |
| `createSecureLog()` | Marks prior open issues resolved and writes a secure/info log. |
| `createLog()` | Creates the actual `dns_security_logs` row. |
| `resolveOpenIssues()` | Backfills `resolved_at` for prior open records of the same type. |
| `dispatchDnsDriftAlerts()` | Sends a `dns_drift` notification when SPF or DMARC regresses from previously secure to missing/critical, throttled once per 24 hours. |
| `shouldDispatchAlert()` | Cache-backed alert throttle helper. |

#### `UniversalSecurityScannerService`

| Method | Behavior |
| --- | --- |
| `__construct(SecurityAlertDispatcher)` | Injects alert dispatcher. |
| `scan(MonitoredDomain $monitoredDomain)` | Performs HTTP audit, SSL audit, missing-header analysis, issue building, security-score calculation, persists a `web_security_scans` row, snapshots SSL info into `monitored_domains.ssl_certificate_info`, and dispatches SSL expiry alerts. |
| `performHttpAudit(string $domain)` | Attempts HTTPS first and HTTP second, measuring status code and response time with 5-second timeout windows. |
| `performSslAudit(string $domain)` | Opens a raw TLS socket, captures peer certificate, parses validity dates and issuer, and returns SSL validity metadata. |
| `extractIssuerName(array $issuer)` | Pulls `O`, then `CN`, then `OU` from certificate issuer data. |
| `resolveMissingHeaders(?Response $response)` | Returns the set of missing critical headers; if the site is unreachable, all critical headers are treated as missing. |
| `buildIssues(array $requestAudit, array $sslAudit, array $missingHeaders)` | Builds operator-facing issue sentences from HTTP, header, and SSL findings. |
| `calculateSecurityScore(...)` | Starts from 100 and subtracts points for missing headers, bad HTTP status, latency, SSL invalidity, and near expiry. |
| `dispatchSslWarningAlert(...)` | Sends an `ssl_warning` alert when a certificate expires in 14 days or less, throttled to once per 24 hours. |

#### `IpIntelligenceService`

| Method | Behavior |
| --- | --- |
| `lookup(string $ipAddress)` | Cache-remembers IP intelligence for 24 hours. |
| `fetchIntelligence(string $ipAddress)` | Calls `http://ip-api.com/json/{ip}` and maps location, ISP, ASN, proxy, and hosting flags. |
| `buildFailurePayload(...)` | Produces a standardized failed-lookup structure. |
| `nullableString(...)` | Optional-string normalizer. |

#### `SecurityAlertDispatcher`

| Method | Behavior |
| --- | --- |
| `dispatch(SecurityAlertNotification $notification)` | Loads all users who have any alert channel enabled and calls `dispatchForUser()` for each. |
| `dispatchForUser(User $user, SecurityAlertNotification $notification)` | Sends email notifications via Laravel notifications, Slack/Discord via webhook POSTs, and Telegram via Bot API if the corresponding user settings are enabled. |
| `postWebhook(...)` | Generic 5-second webhook POST with timeout/error logging. |
| `postTelegram(...)` | Telegram-specific POST wrapper. |

### 6.2 Messaging and analysis services

#### `EmailScannerService`

| Method | Behavior |
| --- | --- |
| `__construct(VirusTotalService)` | Injects the VirusTotal helper. |
| `scanAndStore(User $user, array $email)` | Deduplicates by `google_message_id`, normalizes subject/sender/body/link/PDF inputs, runs the layered security funnel, inserts a `scanned_emails` row, and returns the record plus a `created` flag. |
| `formatResult(ScannedEmail $record, bool $created)` | Returns a frontend-friendly array of the stored email verdict and metadata. |
| `runSecurityFunnel(...)` | Implements the layered email pipeline: whitelist, suspicious TLD shortcut, public-provider + urgent heuristics, scam phrase checks, VirusTotal confirmation, financial attachment extraction, then Gemini AI reasoning. |
| `analyzeWithGemini(...)` | Builds a strict JSON prompt for the Gemini API using sender, body, URLs, extracted links, VT context, financial context, and heuristic flags, retries the call, parses structured JSON, or falls back to a safe error result. |
| `analyzeFinancialAttachments(array $pdfAttachments)` | Runs financial extraction against each PDF and filters null results. |
| `analyzeFinancialPdfAttachment(array $attachment)` | Sends a PDF to Gemini with a structured extraction prompt and returns vendor/payment fields when possible. |
| `parseGeminiResponse(array $payload)` | Extracts the first candidate text, sanitizes it, decodes JSON, and throws if Gemini returns invalid JSON. |
| `sanitizeJsonResponse(string $rawResponse)` | Removes code fences and trims to the outermost JSON object braces. |
| `buildVirusTotalContext(?ScannedUrl $vtResult, array $extractedUrls)` | Produces a structured description of VT findings including vendor flag count and status threshold. |
| `buildAnalysisResult(...)` | Normalizes the scanner output into a single canonical structure including threat flag, severity, verdict, category, reasoning, and analysis chain. |
| `determineSeverity(...)` | Converts verdict/risk score into `clean`, `low`, `medium`, or `high`. |
| `extractUrls(string $text)` | Regex-extracts URLs from message text, capped by count and content length. |
| `buildExtractedUrls(...)` | Merges text-extracted URLs with normalized link objects. |
| `normalizeExtractedLinks(mixed $links)` | Bounds and sanitizes link metadata coming from `LinkExtractionService`. |
| `extractSenderEmail(string $sender)` | Extracts the canonical email address from `From` header text. |
| `jsonPromptValue(mixed $value)` | Pretty-encodes values for Gemini prompt insertion. |
| `normalizeNullableString(mixed $value)` | Converts blank or literal `null` strings to PHP null. |
| `isMockMode()` | Detects mock-vs-live Gemini execution mode from config. |

#### `EmailOriginService`

| Method | Behavior |
| --- | --- |
| `trace(string $rawHeaders)` | Parses raw email headers, extracts public IP hop chains, infers authentication state, runs IP lookups, tries to match trusted providers, flags cloud-host or proxy scenarios, and returns a structured origin-trace array. |
| `parseHeaders(string $rawHeaders)` | Unfolds multiline headers and splits them into name/value/raw structures. |
| `appendHeaderIps(...)` | Adds newly discovered public IPs from a header into the hop sequence. |
| `extractPublicIps(string $headerValue)` | Finds globally routable IPv4/IPv6 values from a header string. |
| `lookupIp(string $ip)` | Cached IP lookup against ip-api.com. |
| `extractAuthenticationState(array $headers)` | Reads SPF, DKIM, and DMARC pass/fail states from `Authentication-Results`. |
| `extractAuthenticationStatus(string $value, string $mechanism)` | Extracts one auth mechanism status from a single header value. |
| `normalizeAuthenticationDecision(array $statuses)` | Reduces multiple auth statuses into `true`, `false`, or `null`. |
| `matchTrustedProvider(array $intelligence)` | Matches provider metadata against Google, Microsoft, Yahoo, Fastmail, and Apple patterns/ASNs. |
| `isCloudHostingProvider(array $intelligence)` | Flags hosting providers when the IP lookup says `hosting = true` and the provider text matches common cloud brands. |
| `hasCloudHostWarning(array $authentication)` | Flags cloud-host warnings when SPF, DKIM, or DMARC fail. |
| `isExplicitProxyOrVpn(array $intelligence)` | Uses the IP-API `proxy` flag. |
| `buildProviderText(array $intelligence)` | Builds a normalized provider text string from ISP/org/ASN data. |

#### `GmailService`

| Method | Behavior |
| --- | --- |
| `__construct(User $user)` | Builds a Google client with configured OAuth credentials and HTTP timeouts, rejects users without tokens, then syncs the stored encrypted tokens into the client. |
| `fetchLatestEmails(int $limit = 10)` | Ensures a valid access token, lists inbox messages, retries once on Google 401 by refreshing tokens, and returns parsed email payload arrays. |
| `executeListMessages(Gmail $service, int $limit)` | Calls Gmail list/get APIs, extracts headers, plain/html body, raw headers, and PDF attachments, and skips malformed messages with warning logs. |
| `extractMessageBody()` | Prefers `text/plain`, otherwise strips HTML into text. |
| `extractHtmlBody()` | Returns `text/html` content if present. |
| `extractBodyByMimeType()` | Recursive MIME tree walker. |
| `extractPdfAttachments()` | Recursively finds PDF parts and fetches attachment payload data when necessary. |
| `decodeBase64Url()` | Converts Gmail base64url payloads into raw text. |
| `base64UrlToBase64()` | Converts base64url to standard base64 padding form. |
| `formatRawHeaders()` | Rebuilds headers into a raw RFC-style string for origin tracing. |
| `syncClientAccessToken()` | Mirrors encrypted DB tokens into the Google client token structure, including expiry metadata. |
| `ensureValidAccessToken()` | Refreshes access token if missing or expired. |
| `refreshAccessToken()` | Uses refresh token to obtain a new access token and persists it back to the user row. |

#### `LinkExtractionService`

| Method | Behavior |
| --- | --- |
| `extractAndInspect(string $htmlBody, string $textBody)` | Caps content length, extracts links from HTML anchors and both HTML/plain-text bodies, normalizes them into structured link objects, and deduplicates by URL hash. |
| `resolveRedirect(string $url)` | Resolves shortened URLs by manually following up to 5 redirect hops with cached results. |
| `extractAnchorTags(string $htmlBody)` | Parses HTML with `DOMDocument` and returns anchor href + anchor text pairs. |
| `extractUrlsFromText(string $text)` | Regex-extracts URL strings from arbitrary text. |
| `storeStructuredLink(array &$links, string $url, ?string $anchorText)` | Normalizes URL and anchor metadata, resolves shorteners, detects visible-text vs destination mismatches, and stores a single structured link record. |
| `normalizeUrl(string $url)` | Ensures the URL is a valid absolute HTTP/HTTPS URL. |
| `trimTrailingPunctuation(string $url)` | Cleans punctuation artifacts at URL edges. |
| `extractDomain(string $url)` | Extracts and normalizes host names. |
| `extractDisplayDomain(string $text)` | Pulls a domain-like string from visible anchor text. |
| `normalizeDomain(string $domain)` | Lowercases and removes `www.`. |
| `shouldResolveRedirect(string $domain)` | Limits redirect expansion to a curated shortener-domain list. |
| `prepareContent(string $content, int $maxLength)` | Removes null bytes and truncates extremely large HTML/text inputs. |

#### `VirusTotalService`

| Method | Behavior |
| --- | --- |
| `scanFirstUrl($emailText)` | In live mode, extracts HTTP/HTTPS URLs, uses only the first one to protect VT quota, returns cached `ScannedUrl` rows when possible, otherwise calls VirusTotal v3, sleeps 15 seconds to respect a 4 req/min limit, stores `url`, `is_malicious`, and `malicious_votes`, and temporarily attaches vendor flag names to the returned model. |

## 7. Database Schema and Models

### 7.1 Core tables

#### Security and DNS domain

| Table | Purpose | Key columns |
| --- | --- | --- |
| `monitored_domains` | Central registry for domains managed by Tier 1/2/3 | `domain`, `infrastructure_type`, `is_active`, `is_owned`, `cloudflare_zone_id`, `app_secret_token`, `auto_ban_threshold`, `last_checked_at`, `ssl_certificate_info` |
| `dns_security_logs` | Point-in-time DNS posture findings | `monitored_domain_id`, `record_type`, `expected_value`, `current_value`, `severity`, `status`, `resolved_at` |
| `web_security_scans` | Point-in-time HTTP/SSL/header audit results | `monitored_domain_id`, `http_status`, `response_time_ms`, `ssl_valid`, `ssl_expires_at`, `ssl_issuer`, `missing_headers`, `security_score`, `detected_issues` |
| `security_threat_logs` | Threat telemetry across Cloudflare and middleware | `monitored_domain_id`, `attacker_ip`, `country`, `path_targeted`, `user_agent`, `event_type`, `severity`, `reason`, `metadata`, `action_taken`, `threat_source`, `detected_at` |
| `blocked_ips` | Canonical banned-IP registry | `monitored_domain_id`, `ip`, `is_global`, `reason` |
| `system_audit_logs` | Administrative action history | `user_id`, `action`, `target_type`, `target_id`, `metadata` |
| `whitelisted_domains` | Trusted sender-domain whitelist for email scanning | `domain`, `description`, `is_active` |

#### Messaging domain

| Table | Purpose | Key columns |
| --- | --- | --- |
| `scanned_emails` | Persisted email analysis results | `user_id`, `google_message_id`, `subject`, `sender`, `snippet`, `is_threat`, `detection_layer`, `severity`, `risk_score`, `reason`, `verdict`, `threat_category`, `analysis_chain`, `final_reasoning`, `origin_trace`, `is_quarantined`, `deleted_at` |
| `scanned_sms` | Persisted SMS analysis results | `user_id`, `sender`, `content`, `is_threat`, `risk_score`, `type`, `explanation`, `deleted_at` |
| `scanned_urls` | Cached VirusTotal URL lookups | `url`, `is_malicious`, `malicious_votes` |

#### User / auth / tenant / queue domain

| Table | Purpose | Key columns |
| --- | --- | --- |
| `users` | Authentication and operator profile | `name`, `email`, `password`, `company_id`, `organization_id`, `role`, `token`, `google_access_token`, `google_refresh_token`, `google_token_expires_at`, `auto_quarantine`, alert settings, `email_verified_at` |
| `companies` | Tenant/company catalog | `name`, `domain`, `is_active` |
| `oauth_tokens` | Legacy/provider OAuth token storage | `company_id`, `user_id`, `provider`, `access_token`, `refresh_token`, `expires_at` |
| `password_reset_tokens` | Laravel password reset broker table | `email`, `token`, `created_at` |
| `sessions` | Laravel session storage | `id`, `user_id`, `ip_address`, `user_agent`, `payload`, `last_activity` |
| `jobs` | Queue jobs table | `queue`, `payload`, `attempts`, `reserved_at`, `available_at`, `created_at` |

### 7.2 Key relationships from models

| Model | Relationships |
| --- | --- |
| `MonitoredDomain` | `hasMany dnsSecurityLogs`, `hasMany webSecurityScans`, `hasOne latestWebSecurityScan`, `hasMany securityThreatLogs`, `hasMany blockedIps` |
| `BlockedIp` | `belongsTo monitoredDomain` |
| `DnsSecurityLog` | `belongsTo monitoredDomain` |
| `SecurityThreatLog` | `belongsTo monitoredDomain` |
| `WebSecurityScan` | `belongsTo monitoredDomain` |
| `SystemAuditLog` | `belongsTo user` |
| `ScannedEmail` | `belongsTo user` |
| `ScannedSms` | `belongsTo user` |
| `User` | `belongsTo company`, `hasOne token` (`OAuthToken`), `hasMany scannedEmails` |
| `Company` | intended `hasMany users`, intended `hasMany tokens` |

### 7.3 Tier-defining columns

#### `monitored_domains`

| Column | Meaning |
| --- | --- |
| `infrastructure_type` | One of `universal`, `cloudflare`, or `app_middleware`. Determines tier semantics. |
| `is_owned` | Marks whether the organization owns the infrastructure and can actively manage it. |
| `cloudflare_zone_id` | Required for Cloudflare-administered domains and used by both threat sync and edge block rule management. |
| `app_secret_token` | Tier 3 bearer token used by external apps to push threat events and pull the block list. Auto-generated on create for middleware domains. |
| `auto_ban_threshold` | Number of Tier 3 threat events from the same IP within 60 seconds required before writing a `blocked_ips` row. Defaults to `10`. |
| `last_checked_at` | Last Tier 1 scan timestamp. |
| `ssl_certificate_info` | Latest SSL/HTTP audit snapshot copied from `web_security_scans`. |

#### `security_threat_logs`

| Column | Meaning |
| --- | --- |
| `attacker_ip` | Source IP of the threat event |
| `country` | Geolocation country when available |
| `path_targeted` | Requested path/route targeted by the attack |
| `user_agent` | Added later to preserve request fingerprinting |
| `event_type` | Nullable machine-readable description of what happened |
| `severity` | Nullable descriptive severity: `info`, `low`, `medium`, `high`, or `critical` |
| `reason` | Nullable human-readable explanation of why the event was reported |
| `metadata` | Nullable JSON containing bounded, sanitized security context |
| `action_taken` | Cloudflare action such as `block`, `challenge`, or middleware `log` |
| `threat_source` | Source such as Cloudflare event source or `app_middleware` |
| `detected_at` | Event timestamp used in uniqueness and analytics |

#### `blocked_ips`

| Column | Meaning |
| --- | --- |
| `monitored_domain_id` | Optional scope anchor for domain-specific bans |
| `ip` | IPv4 or IPv6 string up to 45 chars |
| `is_global` | When `true`, the IP is treated as globally banned for all Tier 3 clients |
| `reason` | Human-readable rationale such as `Auto-banned: exceeded threat threshold` |

### 7.4 Migration chronology

#### Auth / tenant / user migrations

| Migration | Effect |
| --- | --- |
| `0001_01_01_000000_create_users_table` | Creates `users`, `password_reset_tokens`, `sessions`; also seeds a default user row. |
| `2026_02_01_202910_create_saas_table` | Creates `companies` and `oauth_tokens`; adds `company_id` and `role` to `users`. |
| `2026_02_03_135325_add_token_to_users_table` | Adds legacy `users.token`. |
| `2026_02_03_170625_add_org_and_role_to_users_table` | Adds `organization_id` when missing and may add `role` if absent. |
| `2026_02_05_090910_add_default_user` | Inserts a `Super Admin` seed user. |
| `2026_03_08_140423_add_auto_quarantine_to_users_table` | Adds Gmail quarantine toggle. |
| `2026_08_02_000000_add_google_tokens_to_users_table` | Adds dedicated encrypted Google token columns. |
| `2026_08_09_120000_add_security_alert_settings_to_users_table` | Adds email/Slack/Discord/Telegram alert settings. |

#### Messaging migrations

| Migration | Effect |
| --- | --- |
| `2026_02_02_153316_create_scanned_emails_table` | Creates base email scan table. |
| `2026_02_02_215224_add_reason_to_scanned_emails_table` | Adds `reason`. |
| `2026_02_02_221505_add_risk_score_to_scanned_emails_table` | Adds `risk_score`. |
| `2026_02_22_142239_add_detection_layer_to_scanned_emails_table` | Adds `detection_layer`. |
| `2026_03_08_145311_add_is_quarantined_to_scanned_emails_table` | Adds quarantine flag. |
| `2026_03_08_165432_change_columns_to_text_in_scanned_emails_table` | Expands encrypted text fields to `text`. |
| `2026_07_28_120000_add_ai_verdict_fields_to_scanned_emails_table` | Adds verdict, category, chain, and reasoning. |
| `2026_08_08_120000_add_origin_trace_to_scanned_emails_table` | Adds `origin_trace` JSON. |
| `2026_02_03_162311_create_scanned_sms_table` | Creates SMS scan table. |
| `2026_02_03_215056_add_sender_to_scanned_sms_table` | Adds SMS sender column. |
| `2026_02_07_023638_add_soft_deletes_to_scanned_tables` | Adds soft deletes to email and SMS tables. |
| `2026_03_08_155727_create_scanned_urls_table` | Creates VirusTotal URL cache table. |

#### DNS / telemetry migrations

| Migration | Effect |
| --- | --- |
| `2026_02_24_214915_create_whitelisted_domains_table` | Creates trusted-domain whitelist. |
| `2026_08_08_210251_create_monitored_domains_table` | Creates base monitored-domain table. |
| `2026_08_08_231000_add_owned_fields_to_monitored_domains_table` | Adds `is_owned` and `cloudflare_zone_id`. |
| `2026_08_10_120000_add_app_middleware_fields_to_monitored_domains_table` | Adds `infrastructure_type` and `app_secret_token`. |
| `2026_08_15_120000_add_auto_ban_threshold_to_monitored_domains_table` | Adds `auto_ban_threshold`. |
| `2026_08_08_210316_create_dns_securtiy_logs_table` | Creates DNS finding table. |
| `2026_08_08_221500_create_web_security_scans_table` | Creates web/SSL scan table. |
| `2026_08_08_231100_create_security_threat_logs_table` | Creates unified threat telemetry table with uniqueness constraint. |
| `2026_08_10_120100_add_user_agent_to_security_threat_logs_table` | Adds request `user_agent` capture. |
| `2026_08_22_120000_add_threat_details_to_security_threat_logs_table` | Additively adds nullable `event_type`, `severity`, `reason`, and JSON `metadata`. |
| `2026_08_11_120000_create_system_audit_logs_table` | Creates admin audit trail table. |
| `2026_08_15_120100_create_blocked_ips_table` | Creates canonical blocked-IP registry. |

#### Queue migration

| Migration | Effect |
| --- | --- |
| `2026_02_28_185204_create_jobs_table` | Creates Laravel jobs table. |

## 8. Supporting Components Outside the Requested Folders

### 8.1 `SecurityAlertNotification`

This notification class is the transport-agnostic payload formatter used by:

- `AppThreatService`
- `CloudflareThreatService`
- `DnsScannerService`
- `UniversalSecurityScannerService`
- `SecurityAlertDispatcher`

Its public surface:

| Method | Behavior |
| --- | --- |
| `via()` | Mail by default |
| `toMail()` | Human-readable email |
| `toSlackPayload()` | Slack webhook payload |
| `toDiscordPayload()` | Discord webhook payload |
| `toTelegramPayload()` | Telegram Bot API payload |
| `toArray()` | Structured loggable payload |
| `toMarkdownText()` | Shared Markdown body |
| `subjectLine()` | `[SEVERITY] AlertType - domain` |
| `heading()` | Static `DNS Security Alert` heading |

### 8.2 `AppServiceProvider`

Production-only HTTPS forcing via `URL::forceScheme('https')`.

## 9. Observed Architectural Notes and Caveats

These are not speculative redesign ideas; they are implementation realities visible in the current code.

1. There is no inline blocked-IP enforcement middleware in this repository.
   - Tier 3 bans are stored centrally and exported.
   - Tier 2 bans are enforced at Cloudflare when admins create access rules.

2. `AdminDashboardController` still performs manual admin role checks even though admin routes are also wrapped with `EnsureUserIsAdmin`.
   - This duplicates authorization responsibility.

3. Multi-tenant identity is split between `company_id` and `organization_id`.
   - Reporting and admin user management mainly use `organization_id`.
   - The `User` model's `$fillable` list does not currently include `organization_id`, even though admin user creation writes it.

4. `SmsController@analyze()` writes `sender` and `severity` fields, but `ScannedSms::$fillable` currently lists neither.
   - Readers should treat SMS persistence behavior as potentially out of sync with the model whitelist.

5. `Company` model methods declare `HasMany` return types without importing `HasMany`.
   - The intended relationship design is clear, but the file itself is incomplete.

6. `OAuthToken` casts include `is_quarantined`, which is not defined in the shown `oauth_tokens` migration.

7. `emails:cleanup` performs soft deletes, not hard deletes, because `ScannedEmail` uses `SoftDeletes`.
   - The command reduces active visibility but does not physically purge rows.

8. `CloudflareThreatService::processMiddlewareTelemetry()` derives cached blocked IPs from `security_threat_logs.action_taken = 'block'`.
   - Tier 3 ingestion currently writes `action_taken = 'log'`.
   - Actual auto-bans are recorded in `blocked_ips` by `AppThreatService`, so the summary cache is not the canonical enforcement source.

9. Default users are seeded inside migrations.
   - `0001_01_01_000000_create_users_table` inserts a `Wesley Kang` user.
   - `2026_02_05_090910_add_default_user` inserts `admin@example.com`.
   - This means schema migrations also mutate live identity data.

## 10. Quick Reference: Which Components Own Which Responsibilities

| Responsibility | Primary owner |
| --- | --- |
| Domain creation and scan kickoff | `DnsSecurityController@store` |
| DNS record evaluation | `DnsScannerService` |
| HTTP/SSL/header evaluation | `UniversalSecurityScannerService` |
| Cloudflare firewall event sync | `CloudflareThreatService::syncDomainThreats` |
| Tier 3 event ingestion | `Api\TelemetryController` + `AppThreatService` |
| Auto-ban thresholding | `AppThreatService::handleAutoBan` |
| Canonical blocked-IP storage | `blocked_ips` + `BlockedIp` model |
| Blocked-IP export for client apps | `Api\BlockedIpController@index` |
| Cloudflare edge block/unblock | `CloudflareIpBlockService` |
| Alert fanout | `SecurityAlertDispatcher` + `SecurityAlertNotification` |
| Gmail fetch and token refresh | `GmailService` |
| Email threat scoring | `EmailScannerService` |
| Email origin tracing | `EmailOriginService` |
| Link normalization and redirect tracing | `LinkExtractionService` |
| URL reputation | `VirusTotalService` |
| Admin audit trail | `SystemAuditLog` + admin controllers |
