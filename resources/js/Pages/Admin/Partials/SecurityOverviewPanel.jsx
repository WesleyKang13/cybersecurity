import { Link } from '@inertiajs/react';
import {
    Activity,
    AlertTriangle,
    Ban,
    Clock3,
    Globe2,
    MailWarning,
    Server,
    ShieldCheck,
} from 'lucide-react';

const formatCount = (value) => Number(value || 0).toLocaleString();

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Unknown';

const formatEventType = (value) => String(value || '')
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ') || 'Generic Threat';

export default function SecurityOverviewPanel({ overview = {} }) {
    const primaryMetrics = [
        {
            label: 'Threat telemetry events',
            value: overview.threat_events_total,
            helper: `${formatCount(overview.threat_events_last_24_hours)} observed in the last 24 hours`,
            icon: Activity,
            color: 'bg-red-50 text-red-700',
        },
        {
            label: 'High / critical email detections',
            value: overview.high_critical_email_threats,
            helper: `${formatCount(overview.email_threats_total)} total email threat alerts`,
            icon: MailWarning,
            color: 'bg-orange-50 text-orange-700',
        },
        {
            label: 'Active monitored domains',
            value: overview.active_monitored_domains,
            helper: `${formatCount(overview.monitored_domains_total)} configured domains`,
            icon: Globe2,
            color: 'bg-indigo-50 text-indigo-700',
        },
        {
            label: 'Blocked IP entries',
            value: overview.blocked_ips_total,
            helper: 'Current platform blocklist entries',
            icon: Ban,
            color: 'bg-slate-100 text-slate-700',
        },
    ];

    const queueIsHealthy = Number(overview.failed_jobs || 0) === 0;

    return (
        <div className="space-y-6">
            <div>
                <div className="flex items-center gap-3">
                    <div className="rounded-xl bg-indigo-50 p-2.5 text-indigo-700">
                        <ShieldCheck className="h-7 w-7" />
                    </div>
                    <div>
                        <h3 className="text-2xl font-bold text-gray-900">Security Overview</h3>
                        <p className="mt-1 text-sm text-gray-500">
                            High-level platform security posture and operational signals.
                        </p>
                    </div>
                </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                {primaryMetrics.map((metric) => {
                    const Icon = metric.icon;

                    return (
                        <div key={metric.label} className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                            <div className={`inline-flex rounded-lg p-2.5 ${metric.color}`}>
                                <Icon className="h-5 w-5" />
                            </div>
                            <p className="mt-4 text-3xl font-bold text-gray-900">{formatCount(metric.value)}</p>
                            <p className="mt-1 text-sm font-semibold text-gray-800">{metric.label}</p>
                            <p className="mt-1 text-xs leading-5 text-gray-500">{metric.helper}</p>
                        </div>
                    );
                })}
            </div>

            <div className="grid gap-6 xl:grid-cols-3">
                <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm xl:col-span-2">
                    <div className="flex items-center justify-between border-b border-gray-100 bg-gray-50 px-5 py-4">
                        <div>
                            <h4 className="font-semibold text-gray-900">Recent security activity</h4>
                            <p className="mt-1 text-xs text-gray-500">Latest events from the platform telemetry stream.</p>
                        </div>
                        <Link
                            href={route('platform.dashboard', { tab: 'threats' })}
                            className="text-sm font-semibold text-indigo-600 hover:text-indigo-800"
                        >
                            Investigate events
                        </Link>
                    </div>

                    <div className="divide-y divide-gray-100">
                        {(overview.recent_activity || []).length > 0 ? (
                            overview.recent_activity.map((event) => (
                                <div key={event.id} className="flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                                    <div className="min-w-0">
                                        <p className="truncate text-sm font-semibold text-gray-900">
                                            {formatEventType(event.event_type)}
                                            <span className="font-normal text-gray-500"> from </span>
                                            <span className="font-mono text-xs">{event.attacker_ip}</span>
                                        </p>
                                        <p className="mt-1 truncate text-xs text-gray-500">
                                            {event.monitored_domain?.domain || 'Unknown target'}
                                            {event.path_targeted ? ` · ${event.path_targeted}` : ''}
                                            {` · Action: ${event.action_taken || 'Recorded'}`}
                                        </p>
                                    </div>
                                    <span className="shrink-0 text-xs text-gray-500">{formatDate(event.detected_at)}</span>
                                </div>
                            ))
                        ) : (
                            <div className="px-5 py-12 text-center text-sm text-gray-500">
                                No security telemetry has been recorded yet.
                            </div>
                        )}
                    </div>
                </section>

                <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
                    <div className="flex items-center gap-2">
                        <Server className="h-5 w-5 text-indigo-600" />
                        <h4 className="font-semibold text-gray-900">Operational health</h4>
                    </div>
                    <div className="mt-5 space-y-4">
                        <div className="flex items-center justify-between rounded-lg bg-gray-50 px-4 py-3">
                            <div className="flex items-center gap-2 text-sm text-gray-600">
                                <Clock3 className="h-4 w-4" /> Pending jobs
                            </div>
                            <span className="font-bold text-gray-900">{formatCount(overview.pending_jobs)}</span>
                        </div>
                        <div className={`flex items-center justify-between rounded-lg px-4 py-3 ${queueIsHealthy ? 'bg-emerald-50' : 'bg-red-50'}`}>
                            <div className={`flex items-center gap-2 text-sm ${queueIsHealthy ? 'text-emerald-700' : 'text-red-700'}`}>
                                {queueIsHealthy ? <ShieldCheck className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                                Failed jobs
                            </div>
                            <span className={`font-bold ${queueIsHealthy ? 'text-emerald-800' : 'text-red-800'}`}>
                                {formatCount(overview.failed_jobs)}
                            </span>
                        </div>
                    </div>
                    <Link
                        href={route('platform.dashboard', { tab: 'system' })}
                        className="mt-5 inline-flex text-sm font-semibold text-indigo-600 hover:text-indigo-800"
                    >
                        Open System Health
                    </Link>
                </section>
            </div>
        </div>
    );
}
