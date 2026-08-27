import { AlertCircle, Globe2, LoaderCircle, Search, ShieldAlert } from 'lucide-react';
import { useState } from 'react';

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Not observed';

const formatLabel = (value) => String(value || 'unclassified')
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');

const BLOCK_STATUSES = {
    global: {
        label: 'Globally blocked',
        classes: 'border-red-200 bg-red-50 text-red-800',
    },
    domain_specific: {
        label: 'Domain-specific block',
        classes: 'border-amber-200 bg-amber-50 text-amber-800',
    },
    not_blocked: {
        label: 'Not blocked',
        classes: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    },
};

function BlockStatusBadge({ classification }) {
    const status = BLOCK_STATUSES[classification] || BLOCK_STATUSES.not_blocked;

    return (
        <span className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${status.classes}`}>
            {status.label}
        </span>
    );
}

function IntelligenceField({ label, children }) {
    return (
        <div className="rounded-xl border border-gray-200 bg-gray-50 px-4 py-3">
            <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</dt>
            <dd className="mt-1 break-words text-sm font-semibold text-gray-900">{children || 'Unknown'}</dd>
        </div>
    );
}

function Breakdown({ title, items, valueKey = 'value', valueFormatter = formatLabel }) {
    return (
        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white">
            <h5 className="border-b border-gray-100 bg-gray-50 px-4 py-3 text-sm font-semibold text-gray-900">
                {title}
            </h5>
            {items?.length > 0 ? (
                <ul className="divide-y divide-gray-100">
                    {items.map((item) => (
                        <li key={`${item[valueKey]}-${item.count}`} className="flex items-center justify-between gap-4 px-4 py-3 text-sm">
                            <span className="min-w-0 break-words text-gray-700">{valueFormatter(item[valueKey])}</span>
                            <span className="font-semibold tabular-nums text-gray-900">{item.count}</span>
                        </li>
                    ))}
                </ul>
            ) : (
                <p className="px-4 py-5 text-sm text-gray-500">No observations available.</p>
            )}
        </section>
    );
}

export default function GlobalIntelligencePanel({ topAttackers = [] }) {
    const [query, setQuery] = useState('');
    const [investigation, setInvestigation] = useState({
        loading: false,
        data: null,
        error: null,
    });

    const investigate = async (ipAddress) => {
        const normalizedIp = String(ipAddress || '').trim();

        if (!normalizedIp) {
            setInvestigation({ loading: false, data: null, error: 'Enter a valid IP address.' });
            return;
        }

        setQuery(normalizedIp);
        setInvestigation({ loading: true, data: null, error: null });

        try {
            const response = await fetch(`/admin/ip-intelligence/${encodeURIComponent(normalizedIp)}`, {
                headers: {
                    Accept: 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                credentials: 'same-origin',
            });
            const payload = await response.json();

            if (!response.ok || !payload.success) {
                throw new Error(payload.message || 'Unable to investigate this IP address.');
            }

            setInvestigation({ loading: false, data: payload.data, error: null });
        } catch (error) {
            setInvestigation({
                loading: false,
                data: null,
                error: error instanceof Error ? error.message : 'Unable to investigate this IP address.',
            });
        }
    };

    const submitInvestigation = (event) => {
        event.preventDefault();
        investigate(query);
    };

    const intelligence = investigation.data;
    const observations = intelligence?.observations;
    const blockStatus = intelligence?.block_status;

    return (
        <div className="space-y-6">
            <div className="flex items-center gap-3">
                <div className="rounded-xl bg-indigo-50 p-2.5 text-indigo-700">
                    <Globe2 className="h-7 w-7" />
                </div>
                <div>
                    <h3 className="text-2xl font-bold text-gray-900">Global Intelligence</h3>
                    <p className="mt-1 text-sm text-gray-500">
                        Investigate who is attacking the platform and what we know about them.
                    </p>
                </div>
            </div>

            <section className="rounded-xl border border-indigo-100 bg-white p-5 shadow-sm">
                <form onSubmit={submitInvestigation} className="flex flex-col gap-3 sm:flex-row sm:items-end">
                    <label className="flex-1 text-sm font-semibold text-gray-700">
                        Search IP
                        <input
                            type="text"
                            inputMode="text"
                            value={query}
                            onChange={(event) => setQuery(event.target.value)}
                            placeholder="203.0.113.10"
                            className="mt-2 block w-full rounded-lg border-gray-300 font-mono text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                            required
                        />
                    </label>
                    <button
                        type="submit"
                        disabled={investigation.loading}
                        className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        {investigation.loading ? <LoaderCircle className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
                        Investigate
                    </button>
                </form>
            </section>

            {investigation.loading ? (
                <div className="flex items-center gap-3 rounded-xl border border-gray-200 bg-white px-5 py-6 text-sm text-gray-600 shadow-sm">
                    <LoaderCircle className="h-5 w-5 animate-spin text-indigo-600" />
                    Loading IP intelligence and CyberSafe observations...
                </div>
            ) : null}

            {investigation.error ? (
                <div className="flex items-center gap-3 rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-800">
                    <AlertCircle className="h-5 w-5 shrink-0" />
                    {investigation.error}
                </div>
            ) : null}

            {intelligence ? (
                <div className="space-y-6">
                    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                        <div className="flex flex-col gap-3 border-b border-gray-100 pb-4 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">Attacker identity · IP address</p>
                                <h4 className="mt-1 font-mono text-2xl font-bold text-gray-900">{intelligence.ip}</h4>
                            </div>
                            <BlockStatusBadge classification={blockStatus?.classification} />
                        </div>

                        <dl className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                            <IntelligenceField label="Country">
                                {[intelligence.country, intelligence.countryCode].filter(Boolean).join(' · ')}
                            </IntelligenceField>
                            <IntelligenceField label="Region / City">
                                {[intelligence.regionName, intelligence.city].filter(Boolean).join(', ')}
                            </IntelligenceField>
                            <IntelligenceField label="ISP">{intelligence.isp}</IntelligenceField>
                            <IntelligenceField label="Organization">{intelligence.org}</IntelligenceField>
                            <IntelligenceField label="ASN">{intelligence.as}</IntelligenceField>
                            <IntelligenceField label="Hosting indicator">{intelligence.hosting ? 'Yes' : 'No'}</IntelligenceField>
                            <IntelligenceField label="Proxy / VPN indicator">{intelligence.proxy ? 'Yes' : 'No'}</IntelligenceField>
                            <IntelligenceField label="Mobile network">{intelligence.mobile ? 'Yes' : 'No'}</IntelligenceField>
                        </dl>

                        {blockStatus?.domain_specific_blocks?.length > 0 ? (
                            <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                                <p className="font-semibold">Blocked for specific domains</p>
                                <p className="mt-1">
                                    {blockStatus.domain_specific_blocks.map((block) => block.domain).join(', ')}
                                </p>
                            </div>
                        ) : null}
                    </section>

                    <section className="space-y-4">
                        <div>
                            <h4 className="text-xl font-bold text-gray-900">CyberSafe observations</h4>
                            <p className="mt-1 text-sm text-gray-500">Platform telemetry scoped only to this attacker IP.</p>
                        </div>

                        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                            {[
                                ['Total events', observations?.total_events ?? 0],
                                ['Applications targeted', observations?.applications_targeted ?? 0],
                                ['First seen', formatDate(observations?.first_seen)],
                                ['Last seen', formatDate(observations?.last_seen)],
                            ].map(([label, value]) => (
                                <div key={label} className="rounded-xl border border-gray-200 bg-white px-4 py-4 shadow-sm">
                                    <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</p>
                                    <p className="mt-2 text-lg font-bold text-gray-900">{value}</p>
                                </div>
                            ))}
                        </div>

                        <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
                            <Breakdown title="Threat types" items={observations?.threat_types} />
                            <Breakdown title="Severities" items={observations?.severities} />
                            <Breakdown title="Actions taken" items={observations?.actions_taken} />
                            <Breakdown title="Threat sources" items={observations?.threat_sources} />
                            <Breakdown
                                title="Applications targeted"
                                items={observations?.top_applications}
                                valueKey="domain"
                                valueFormatter={(value) => value}
                            />
                            <Breakdown
                                title="Top targeted paths"
                                items={observations?.top_targeted_paths}
                                valueKey="path"
                                valueFormatter={(value) => value}
                            />
                        </div>
                    </section>
                </div>
            ) : null}

            <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
                <div className="border-b border-gray-100 bg-gray-50 px-5 py-4">
                    <h4 className="flex items-center text-base font-semibold text-gray-900">
                        <ShieldAlert className="mr-2 h-5 w-5 text-red-600" />
                        Top Attackers
                    </h4>
                    <p className="mt-1 text-sm text-gray-500">Highest-volume attacker identities observed across platform telemetry.</p>
                </div>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-white">
                            <tr>
                                {['Attacker IP', 'Country', 'Total events', 'Applications targeted', 'Most recent event', 'Blocked status'].map((heading) => (
                                    <th key={heading} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">
                                        {heading}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 bg-white">
                            {topAttackers.length > 0 ? topAttackers.map((attacker) => (
                                <tr key={attacker.attacker_ip} className="hover:bg-gray-50">
                                    <td className="px-5 py-4">
                                        <button
                                            type="button"
                                            onClick={() => investigate(attacker.attacker_ip)}
                                            className="font-mono text-sm font-semibold text-indigo-600 hover:underline"
                                        >
                                            {attacker.attacker_ip}
                                        </button>
                                    </td>
                                    <td className="px-5 py-4 text-sm text-gray-600">{attacker.country || 'Unknown'}</td>
                                    <td className="px-5 py-4 text-sm font-semibold tabular-nums text-gray-900">{attacker.total_events}</td>
                                    <td className="px-5 py-4 text-sm tabular-nums text-gray-600">{attacker.applications_targeted}</td>
                                    <td className="whitespace-nowrap px-5 py-4 text-sm text-gray-600">{formatDate(attacker.most_recent_event)}</td>
                                    <td className="px-5 py-4"><BlockStatusBadge classification={attacker.blocked_status} /></td>
                                </tr>
                            )) : (
                                <tr>
                                    <td colSpan="6" className="px-6 py-10 text-center text-sm text-gray-500">
                                        No attacker observations are available yet.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
}
