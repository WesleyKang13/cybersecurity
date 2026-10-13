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
    cloudflare_ip_access_rule_active: {
        label: 'Cloudflare IP Access Rule active',
        classes: 'border-red-200 bg-red-50 text-red-800',
    },
    tier3_global_block_list_entry: {
        label: 'Tier 3 global block-list entry',
        classes: 'border-amber-200 bg-amber-50 text-amber-800',
    },
    tier3_domain_block_list_entry: {
        label: 'Tier 3 domain block-list entry',
        classes: 'border-amber-200 bg-amber-50 text-amber-800',
    },
    unknown: {
        label: 'Cloudflare status not synced',
        classes: 'border-gray-300 bg-gray-100 text-gray-700',
    },
    no_known_block: {
        label: 'No known block',
        classes: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    },
};

function BlockStatusBadge({ classification }) {
    const status = BLOCK_STATUSES[classification] || BLOCK_STATUSES.unknown;

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

                        <div className="mt-4 grid gap-3 lg:grid-cols-2">
                            <div className="rounded-xl border border-indigo-100 bg-indigo-50 px-4 py-3 text-sm text-indigo-950">
                                <p className="font-semibold">Tier 2 · Cloudflare</p>
                                {blockStatus?.tier_2?.status === 'active' ? (
                                    <p className="mt-1">Confirmed active IP Access Rule for {blockStatus.tier_2.active_ip_access_rules.map((rule) => rule.domain).join(', ')}.</p>
                                ) : blockStatus?.tier_2?.status === 'not_active' ? (
                                    <p className="mt-1">No active IP Access Rule was found in the {blockStatus.tier_2.checked_domains?.length || 0} synced Cloudflare zone(s).</p>
                                ) : blockStatus?.tier_2?.status === 'unknown' ? (
                                    <p className="mt-1">Unknown / not synced. Cloudflare rule status could not be verified for {blockStatus.tier_2.unavailable_domains?.map((domain) => domain.domain).join(', ') || 'one or more configured zones'}.</p>
                                ) : (
                                    <p className="mt-1">No Cloudflare-backed domain associated with this IP’s telemetry is available to verify.</p>
                                )}
                            </div>
                            <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-950">
                                <p className="font-semibold">Tier 3 · local client enforcement</p>
                                {blockStatus?.tier_3?.global_block_list_entry ? (
                                    <p className="mt-1">Published on the Tier 3 global block list. {blockStatus.tier_3.enforcement_note}</p>
                                ) : blockStatus?.tier_3?.domain_block_list_entries?.length > 0 ? (
                                    <p className="mt-1">Published for {blockStatus.tier_3.domain_block_list_entries.map((block) => block.domain).join(', ')}. {blockStatus.tier_3.enforcement_note}</p>
                                ) : (
                                    <p className="mt-1">No Tier 3 block-list entry is recorded for this IP.</p>
                                )}
                            </div>
                        </div>
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

                        <section className="overflow-hidden rounded-xl border border-gray-200 bg-white">
                            <h5 className="border-b border-gray-100 bg-gray-50 px-4 py-3 text-sm font-semibold text-gray-900">Recent attacker activity</h5>
                            {observations?.recent_activity?.length > 0 ? (
                                <ol className="divide-y divide-gray-100">
                                    {observations.recent_activity.map((event) => (
                                        <li key={event.id} className="grid gap-2 px-4 py-3 text-sm sm:grid-cols-[minmax(9rem,auto)_1fr_auto] sm:items-center">
                                            <span className="text-gray-500">{formatDate(event.detected_at)}</span>
                                            <span className="min-w-0"><span className="font-semibold text-gray-900">{formatLabel(event.event_type || 'unclassified')}</span><span className="ml-2 break-all font-mono text-xs text-gray-500">{event.path_targeted || '/'}</span><span className="mt-1 block text-xs text-gray-500">{event.domain} · {event.source_label}</span></span>
                                            <span className="text-xs font-semibold text-gray-700">{event.action_label}</span>
                                        </li>
                                    ))}
                                </ol>
                            ) : (
                                <p className="px-4 py-5 text-sm text-gray-500">No attacker activity has been observed yet.</p>
                            )}
                        </section>
                    </section>
                </div>
            ) : null}

            <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
                <div className="border-b border-gray-100 bg-gray-50 px-5 py-4">
                    <h4 className="flex items-center text-base font-semibold text-gray-900">
                        <ShieldAlert className="mr-2 h-5 w-5 text-red-600" />
                        Top Attackers
                    </h4>
                    <p className="mt-1 text-sm text-gray-500">Highest-volume attacker identities observed across platform telemetry. Inspect an IP to sync its Cloudflare IP Access Rule status.</p>
                </div>
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-white">
                            <tr>
                                {['Attacker IP', 'Country', 'Total events', 'Applications targeted', 'Most recent event', 'Tier 3 list status'].map((heading) => (
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
                                    <td className="px-5 py-4"><BlockStatusBadge classification={attacker.tier_3_status === 'global_block_list_entry' ? 'tier3_global_block_list_entry' : attacker.tier_3_status === 'domain_block_list_entry' ? 'tier3_domain_block_list_entry' : 'no_known_block'} /></td>
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
