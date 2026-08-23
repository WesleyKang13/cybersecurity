import Modal from '@/Components/Modal';
import PrimaryButton from '@/Components/PrimaryButton';
import SecondaryButton from '@/Components/SecondaryButton';
import { CheckCircle2, Copy } from 'lucide-react';
import { useState } from 'react';

const STEP_STYLES = {
    active: 'border-indigo-500 bg-indigo-50 text-indigo-700 dark:border-indigo-400 dark:bg-indigo-500/10 dark:text-indigo-200',
    inactive: 'border-gray-200 bg-white text-gray-600 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:bg-gray-800',
};

function CodePanel({ blockId, code, language, title, copiedBlockId, onCopy }) {
    return (
        <div className="rounded-2xl border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-900/60">
            <div className="flex items-center justify-between gap-3 border-b border-gray-200 px-4 py-3 dark:border-gray-700">
                <div>
                    <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">{title}</p>
                    <p className="mt-1 text-xs uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">{language}</p>
                </div>
                <button
                    type="button"
                    onClick={() => onCopy(blockId, code)}
                    className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-3 py-2 text-xs font-semibold text-gray-700 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                >
                    {copiedBlockId === blockId ? (
                        <>
                            <CheckCircle2 className="mr-2 h-4 w-4" />
                            Copied
                        </>
                    ) : (
                        <>
                            <Copy className="mr-2 h-4 w-4" />
                            Copy
                        </>
                    )}
                </button>
            </div>
            <pre className="overflow-x-auto px-4 py-4 text-xs leading-6 text-gray-800 dark:text-gray-200">
                <code>{code}</code>
            </pre>
        </div>
    );
}

export default function Tier3IntegrationGuideModal({
    isOpen,
    onClose,
    domainName,
    appSecretToken,
}) {
    const [activeStep, setActiveStep] = useState('env');
    const [copiedBlockId, setCopiedBlockId] = useState(null);

    const tokenValue = String(appSecretToken || '').trim() || 'YOUR_APP_SECRET_TOKEN';
    const normalizedDomainName = String(domainName || '').trim() || 'your-app.example.com';

    const snippets = {
        env: `SECURITY_MANAGER_URL=https://your-security-manager-domain.com
SECURITY_MANAGER_TOKEN=${tokenValue}
SECURITY_MANAGER_DOMAIN=${normalizedDomainName}`,
        client: `<?php

namespace App\\Services;

use Illuminate\\Support\\Facades\\Http;

class SecurityTelemetryClient
{
    public function reportThreat(
        string $attackerIp,
        string $targetedPath,
        string $userAgent,
        ?string $eventType = null,
        ?string $severity = null,
        ?string $reason = null,
        array $metadata = [],
    ): void {
        $threat = [
            'attacker_ip' => $attackerIp,
            'targeted_path' => $targetedPath,
            'user_agent' => $userAgent,
            'timestamp' => now()->toIso8601String(),
        ];

        foreach ([
            'event_type' => $eventType,
            'severity' => $severity,
            'reason' => $reason,
        ] as $field => $value) {
            if ($value !== null) {
                $threat[$field] = $value;
            }
        }

        if ($metadata !== []) {
            $threat['metadata'] = $metadata;
        }

        Http::timeout(5)
            ->acceptJson()
            ->withToken(env('SECURITY_MANAGER_TOKEN'))
            ->post(rtrim(env('SECURITY_MANAGER_URL'), '/') . '/api/v1/telemetry/threats', [
                'threats' => [$threat],
            ])
            ->throw();
    }

    public function blockedIps(): array
    {
        $response = Http::timeout(5)
            ->acceptJson()
            ->withToken(env('SECURITY_MANAGER_TOKEN'))
            ->get(rtrim(env('SECURITY_MANAGER_URL'), '/') . '/api/v1/telemetry/blocked-ips')
            ->throw();

        return array_values(array_filter($response->json(), 'is_string'));
    }
}`,
        middleware: `<?php

namespace App\\Http\\Middleware;

use App\\Services\\SecurityTelemetryClient;
use Closure;
use Illuminate\\Http\\Request;
use Symfony\\Component\\HttpFoundation\\Response;

class SecurityTelemetryMiddleware
{
    public function __construct(
        private readonly SecurityTelemetryClient $telemetryClient
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $blockedIps = cache()->remember(
            'security-manager:blocked-ips',
            now()->addMinutes(5),
            fn () => $this->telemetryClient->blockedIps()
        );

        $clientIp = (string) $request->ip();

        if (in_array($clientIp, $blockedIps, true)) {
            abort(403, 'Access denied.');
        }

        $classification = $this->classifySuspiciousRequest($request);

        if ($classification !== null) {
            rescue(function () use ($request, $clientIp, $classification): void {
                $this->telemetryClient->reportThreat(
                    attackerIp: $clientIp,
                    targetedPath: '/' . ltrim($request->path(), '/'),
                    userAgent: (string) $request->userAgent(),
                    eventType: $classification['event_type'],
                    severity: $classification['severity'],
                    reason: $classification['reason'],
                    metadata: [
                        'matched_pattern' => $classification['matched_pattern'],
                        'http_method' => $request->method(),
                    ],
                );
            }, report: false);
        }

        return $next($request);
    }

    private function classifySuspiciousRequest(Request $request): ?array
    {
        $path = strtolower('/' . ltrim($request->path(), '/'));
        $signatures = [
            [
                'needle' => '.env',
                'event_type' => 'environment_file_probe',
                'severity' => 'high',
                'reason' => 'Attempt to access environment configuration file',
            ],
            [
                'needle' => 'wp-admin',
                'event_type' => 'wordpress_admin_probe',
                'severity' => 'medium',
                'reason' => 'Probe for WordPress administrative endpoint',
            ],
            [
                'needle' => 'phpmyadmin',
                'event_type' => 'phpmyadmin_probe',
                'severity' => 'medium',
                'reason' => 'Probe for phpMyAdmin endpoint',
            ],
            [
                'needle' => 'test-middleware',
                'event_type' => 'test_probe',
                'severity' => 'low',
                'reason' => 'Tier 3 telemetry development test',
                'local_only' => true,
            ],
        ];

        foreach ($signatures as $signature) {
            if (($signature['local_only'] ?? false) && !app()->environment('local')) {
                continue;
            }

            if (str_contains($path, $signature['needle'])) {
                return [
                    'event_type' => $signature['event_type'],
                    'severity' => $signature['severity'],
                    'reason' => $signature['reason'],
                    'matched_pattern' => $signature['needle'],
                ];
            }
        }

        return null;
    }
}`,
        registration: `<?php

// bootstrap/app.php (Laravel 11/12 protected application)

use App\\Http\\Middleware\\SecurityTelemetryMiddleware;
use Illuminate\\Foundation\\Application;
use Illuminate\\Foundation\\Configuration\\Exceptions;
use Illuminate\\Foundation\\Configuration\\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->web(append: [
            SecurityTelemetryMiddleware::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // Keep the protected application's existing exception configuration.
    })
    ->create();

// If your application uses another Laravel version, register the middleware
// in that version's normal global/web middleware configuration.`,
        failedLogin: `<?php

namespace App\\Listeners;

use App\\Services\\SecurityTelemetryClient;
use Illuminate\\Auth\\Events\\Failed;

class ReportFailedLogin
{
    public function __construct(
        private readonly SecurityTelemetryClient $telemetryClient
    ) {
    }

    public function handle(Failed $event): void
    {
        $request = request();

        rescue(function () use ($request): void {
            $this->telemetryClient->reportThreat(
                attackerIp: (string) $request->ip(),
                targetedPath: '/login',
                userAgent: (string) $request->userAgent(),
                eventType: 'failed_login',
                severity: 'medium',
                reason: 'Authentication failed',
            );
        }, report: false);

        // Never read or transmit $event->credentials: it can contain the password.
    }
}

// Laravel 12 discovers listeners in app/Listeners by default. If event discovery
// is disabled in your application, register ReportFailedLogin for Failed::class
// explicitly in your application's event provider.`,
        test: `# Run only against a development/staging manager and client token.
TEST_TIMESTAMP="$(date -Iseconds)"

curl --request POST 'https://your-security-manager-domain.com/api/v1/telemetry/threats' \\
  --header 'Accept: application/json' \\
  --header 'Content-Type: application/json' \\
  --header 'Authorization: Bearer ${tokenValue}' \\
  --data "{\\"threats\\":[{\\"attacker_ip\\":\\"192.0.2.10\\",\\"targeted_path\\":\\"/test-middleware\\",\\"user_agent\\":\\"Tier3-Development-Test/1.0\\",\\"timestamp\\":\\"\${TEST_TIMESTAMP}\\",\\"event_type\\":\\"test_probe\\",\\"severity\\":\\"low\\",\\"reason\\":\\"Tier 3 telemetry development test\\",\\"metadata\\":{\\"test_run\\":true}}]}"`,
    };

    const steps = [
        {
            id: 'env',
            title: 'Step 1: Environment Setup',
            summary: 'Add the manager base URL and the Tier 3 bearer token to your application environment.',
            language: '.env',
            code: snippets.env,
            note: 'Store the token as a secret. Rotating the token in the SOC dashboard requires updating this value immediately in the client application.',
        },
        {
            id: 'client',
            title: 'Step 2: Telemetry Client',
            summary: 'Create a small service that can report threat events and fetch the current blocked IP list.',
            language: 'PHP / Laravel',
            code: snippets.client,
            note: 'This uses the live Tier 3 endpoints: POST /api/v1/telemetry/threats and GET /api/v1/telemetry/blocked-ips.',
        },
        {
            id: 'middleware',
            title: 'Step 3: Middleware Wiring',
            summary: 'Call the client from application middleware so suspicious requests are reported and blocked IPs are enforced locally.',
            language: 'PHP / Laravel',
            code: snippets.middleware,
            note: 'The existing .env, wp-admin, and phpMyAdmin detections are enriched without changing block behavior. test-middleware is reported only when APP_ENV=local.',
        },
        {
            id: 'registration',
            title: 'Step 4: Registration',
            summary: 'Register the middleware in the protected application web pipeline.',
            language: 'PHP / Laravel',
            code: snippets.registration,
            note: 'The middleware polls the central blocked-IP list, caches it for five minutes, and returns 403 for addresses already blocked by the existing central policy.',
        },
        {
            id: 'failedLogin',
            title: 'Step 5: Failed Login',
            summary: 'Optionally listen for Laravel authentication failures and report sanitized context without credentials.',
            language: 'PHP / Laravel',
            code: snippets.failedLogin,
            note: 'Applications without authentication do not need this listener. Never access or transmit the Failed event credentials array.',
        },
        {
            id: 'test',
            title: 'Step 6: Development Test',
            summary: 'Send one safe enriched test event and confirm it appears in Threat Overview.',
            language: 'Shell / curl',
            code: snippets.test,
            note: 'Expected result: Test Probe, Low, /test-middleware, reason "Tier 3 telemetry development test", and action LOG. Do not expose a dedicated test route in production.',
        },
    ];

    const activeStepConfig = steps.find((step) => step.id === activeStep) ?? steps[0];

    const copySnippet = async (blockId, code) => {
        if (!navigator?.clipboard?.writeText) {
            return;
        }

        try {
            await navigator.clipboard.writeText(code);
            setCopiedBlockId(blockId);
            window.setTimeout(() => {
                setCopiedBlockId((current) => (current === blockId ? null : current));
            }, 2000);
        } catch (error) {
            setCopiedBlockId(null);
        }
    };

    return (
        <Modal show={isOpen} onClose={onClose} maxWidth="4xl">
            <div className="max-h-[85vh] overflow-y-auto bg-white p-6 dark:bg-gray-800">
                <div className="flex flex-col gap-4 border-b border-gray-200 pb-6 dark:border-gray-700 lg:flex-row lg:items-start lg:justify-between">
                    <div>
                        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Tier 3 Integration Guide</h2>
                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                            Ready-to-use middleware integration guidance for <span className="font-semibold text-gray-700 dark:text-gray-200">{normalizedDomainName}</span>.
                        </p>
                    </div>
                    <div className="rounded-2xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm text-cyan-900 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-100">
                        Uses the live Tier 3 telemetry API with the current bearer token already injected into the examples.
                    </div>
                </div>

                <div className="mt-6 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {steps.map((step) => (
                        <button
                            key={step.id}
                            type="button"
                            onClick={() => setActiveStep(step.id)}
                            className={`rounded-2xl border px-4 py-4 text-left transition ${activeStep === step.id ? STEP_STYLES.active : STEP_STYLES.inactive}`}
                        >
                            <p className="text-sm font-semibold">{step.title}</p>
                            <p className="mt-2 text-xs leading-5 opacity-90">{step.summary}</p>
                        </button>
                    ))}
                </div>

                <div className="mt-6 space-y-4">
                    <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 dark:border-gray-700 dark:bg-gray-900/60">
                        <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">{activeStepConfig.title}</p>
                        <p className="mt-2 text-sm leading-6 text-gray-600 dark:text-gray-300">{activeStepConfig.summary}</p>
                        <p className="mt-3 text-xs leading-5 text-gray-500 dark:text-gray-400">{activeStepConfig.note}</p>
                    </div>

                    <CodePanel
                        blockId={activeStepConfig.id}
                        code={activeStepConfig.code}
                        language={activeStepConfig.language}
                        title={activeStepConfig.title}
                        copiedBlockId={copiedBlockId}
                        onCopy={copySnippet}
                    />
                </div>

                <div className="mt-6 grid gap-4 lg:grid-cols-2">
                    <section className="rounded-2xl border border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900/60">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Field semantics and compatibility</h3>
                        <dl className="mt-3 space-y-2 text-xs leading-5 text-gray-600 dark:text-gray-300">
                            <div><dt className="inline font-semibold">event_type:</dt> <dd className="inline">what happened, using a short machine-readable identifier.</dd></div>
                            <div><dt className="inline font-semibold">severity:</dt> <dd className="inline">how serious it is: info, low, medium, high, or critical.</dd></div>
                            <div><dt className="inline font-semibold">reason:</dt> <dd className="inline">why the application reported it.</dd></div>
                            <div><dt className="inline font-semibold">action_taken:</dt> <dd className="inline">what the central system did; it remains separate and is not sent by this client.</dd></div>
                        </dl>
                        <p className="mt-3 text-xs leading-5 text-gray-500 dark:text-gray-400">
                            Existing three-argument reportThreat calls remain valid. The client still adds timestamp automatically, and all enrichment fields are optional.
                        </p>
                        <pre className="mt-3 overflow-x-auto rounded-xl bg-gray-900 p-3 font-mono text-[11px] leading-5 text-gray-100">{`// Existing usage remains valid:
$client->reportThreat($request->ip(), '/admin', (string) $request->userAgent());

// event_type = WHAT, severity = HOW serious, reason = WHY.
// action_taken = WHAT the central system did (for ingestion: log).
$client->reportThreat(
    attackerIp: (string) $request->ip(),
    targetedPath: '/login',
    userAgent: (string) $request->userAgent(),
    eventType: 'failed_login',
    severity: 'medium',
    reason: 'Authentication failed',
);`}</pre>
                    </section>

                    <section className="rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-900/60 lg:col-span-2">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Classification reference</h3>
                        <div className="mt-3 overflow-x-auto">
                            <table className="min-w-full text-left text-xs text-gray-600 dark:text-gray-300">
                                <thead><tr className="border-b border-gray-200 dark:border-gray-700"><th className="pb-2 pr-4">Signal</th><th className="pb-2 pr-4">event_type</th><th className="pb-2">Suggested severity</th></tr></thead>
                                <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                                    <tr><td className="py-2 pr-4">.env probe</td><td className="py-2 pr-4 font-mono">environment_file_probe</td><td className="py-2">high</td></tr>
                                    <tr><td className="py-2 pr-4">wp-admin probe</td><td className="py-2 pr-4 font-mono">wordpress_admin_probe</td><td className="py-2">medium</td></tr>
                                    <tr><td className="py-2 pr-4">phpMyAdmin probe</td><td className="py-2 pr-4 font-mono">phpmyadmin_probe</td><td className="py-2">medium</td></tr>
                                    <tr><td className="py-2 pr-4">Failed login</td><td className="py-2 pr-4 font-mono">failed_login</td><td className="py-2">medium</td></tr>
                                    <tr><td className="py-2 pr-4">Repeated failures already identified by the app</td><td className="py-2 pr-4 font-mono">brute_force</td><td className="py-2">high</td></tr>
                                    <tr><td className="py-2 pr-4">Other suspicious request</td><td className="py-2 pr-4 font-mono">suspicious_request</td><td className="py-2">low or medium</td></tr>
                                    <tr><td className="py-2 pr-4">Local development check</td><td className="py-2 pr-4 font-mono">test_probe</td><td className="py-2">low</td></tr>
                                </tbody>
                            </table>
                        </div>
                        <p className="mt-3 text-xs leading-5 text-gray-500 dark:text-gray-400">
                            Severity is descriptive only. The manager does not infer brute force or change blocking based on severity; existing report-count auto-ban behavior remains unchanged.
                        </p>
                    </section>

                    <section className="rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-900/60 lg:col-span-2">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">API limits</h3>
                        <p className="mt-2 text-xs leading-5 text-gray-600 dark:text-gray-300">
                            The full JSON request is limited to 512 KB, and each request accepts 1–100 events. event_type is lowercase snake_case up to 100 characters; reason is up to 2,000 characters; targeted_path is up to 2,048 characters; and user_agent is up to 10,000 characters. Metadata is a JSON object/array limited to 16 KB, 6 nesting levels, and 100 values. Invalid canonical severity values are rejected with HTTP 422.
                        </p>
                    </section>

                    <section className="rounded-2xl border border-red-200 bg-red-50 p-4 dark:border-red-500/30 dark:bg-red-500/10">
                        <h3 className="text-sm font-semibold text-red-900 dark:text-red-100">Sanitized metadata only</h3>
                        <p className="mt-2 text-xs leading-5 text-red-800 dark:text-red-200">
                            Metadata may contain small context such as a matched rule, HTTP method, status code, or attempt count. Never send passwords, Authorization headers, cookies, session IDs, OAuth/API tokens, API secrets, payment details, private keys, complete request bodies, or .env contents. Sensitive keys are rejected.
                        </p>
                    </section>

                    <section className="rounded-2xl border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-900/60 lg:col-span-2">
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Troubleshooting</h3>
                        <ul className="mt-2 grid gap-2 text-xs leading-5 text-gray-600 dark:text-gray-300 md:grid-cols-2">
                            <li>401: verify the bearer token, active domain, and SECURITY_MANAGER_TOKEN.</li>
                            <li>Connection error: verify SECURITY_MANAGER_URL and reachability from the protected app.</li>
                            <li>Block not visible yet: the sample client caches blocked IPs for five minutes.</li>
                            <li>Unclassified event: the sending client used the legacy payload without enrichment.</li>
                            <li>422: use a canonical lowercase severity and respect field/metadata limits.</li>
                            <li>Production: remove development routes and keep the local-only test rule gated by APP_ENV.</li>
                        </ul>
                    </section>
                </div>

                <div className="mt-6 flex justify-end gap-3">
                    <SecondaryButton onClick={onClose}>Close</SecondaryButton>
                    <PrimaryButton onClick={() => copySnippet(activeStepConfig.id, activeStepConfig.code)}>
                        {copiedBlockId === activeStepConfig.id ? (
                            <>
                                <CheckCircle2 className="mr-2 h-4 w-4" />
                                Copied Current Step
                            </>
                        ) : (
                            <>
                                <Copy className="mr-2 h-4 w-4" />
                                Copy Current Step
                            </>
                        )}
                    </PrimaryButton>
                </div>
            </div>
        </Modal>
    );
}
