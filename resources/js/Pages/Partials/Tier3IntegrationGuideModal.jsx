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
    public function reportThreat(string $attackerIp, string $targetedPath, string $userAgent): void
    {
        Http::timeout(5)
            ->acceptJson()
            ->withToken(env('SECURITY_MANAGER_TOKEN'))
            ->post(rtrim(env('SECURITY_MANAGER_URL'), '/') . '/api/v1/telemetry/threats', [
                'threats' => [[
                    'attacker_ip' => $attackerIp,
                    'targeted_path' => $targetedPath,
                    'user_agent' => $userAgent,
                    'timestamp' => now()->toIso8601String(),
                ]],
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

        if ($this->looksSuspicious($request)) {
            rescue(function () use ($request, $clientIp): void {
                $this->telemetryClient->reportThreat(
                    attackerIp: $clientIp,
                    targetedPath: '/' . ltrim($request->path(), '/'),
                    userAgent: (string) $request->userAgent()
                );
            }, report: false);
        }

        return $next($request);
    }

    private function looksSuspicious(Request $request): bool
    {
        return str_contains($request->path(), '.env')
            || str_contains($request->path(), 'wp-admin')
            || str_contains($request->path(), 'phpmyadmin');
    }
}`,
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
            note: 'Tune the suspicious-request logic to match your own attack signatures, application routes, and logging policy.',
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

                <div className="mt-6 grid gap-3 lg:grid-cols-3">
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
