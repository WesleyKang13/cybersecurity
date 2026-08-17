import { CheckCircle, ShieldAlert } from 'lucide-react';

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Unknown';

const truncateText = (value, maxLength = 90) => {
    const text = String(value || '').trim();

    return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
};

export default function ThreatOverviewPanel({ events = [], onInspectIp }) {
    return (
        <div className="space-y-6">
            <div className="flex items-center gap-3">
                <div className="rounded-xl bg-red-50 p-2.5 text-red-700">
                    <ShieldAlert className="h-7 w-7" />
                </div>
                <div>
                    <h3 className="text-2xl font-bold text-gray-900">Threat Overview</h3>
                    <p className="mt-1 text-sm text-gray-500">
                        Investigate the 100 most recent events received through platform threat telemetry.
                    </p>
                </div>
            </div>

            <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                {['Detected', 'Source', 'Attacker', 'Affected target', 'Action', 'Details'].map((heading) => (
                                    <th key={heading} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">
                                        {heading}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 bg-white">
                            {events.length > 0 ? (
                                events.map((event) => (
                                    <tr key={event.id} className="align-top transition hover:bg-gray-50/70">
                                        <td className="whitespace-nowrap px-5 py-4 text-xs text-gray-600">
                                            {formatDate(event.detected_at)}
                                        </td>
                                        <td className="px-5 py-4">
                                            <span className="inline-flex rounded-full bg-purple-50 px-2.5 py-1 text-xs font-semibold text-purple-700">
                                                {event.threat_source || 'Telemetry'}
                                            </span>
                                        </td>
                                        <td className="px-5 py-4">
                                            <button
                                                type="button"
                                                onClick={() => onInspectIp(event.attacker_ip)}
                                                className="font-mono text-xs font-semibold text-blue-600 hover:underline"
                                            >
                                                {event.attacker_ip}
                                            </button>
                                            <p className="mt-1 text-xs text-gray-500">{event.country || 'Unknown location'}</p>
                                        </td>
                                        <td className="px-5 py-4">
                                            <p className="text-sm font-semibold text-gray-900">
                                                {event.monitored_domain?.domain || 'Unknown application'}
                                            </p>
                                            <p className="mt-1 max-w-xs truncate font-mono text-xs text-gray-500" title={event.path_targeted || ''}>
                                                {event.path_targeted || 'No targeted path recorded'}
                                            </p>
                                        </td>
                                        <td className="px-5 py-4">
                                            <span className="inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
                                                {event.action_taken || 'Recorded'}
                                            </span>
                                        </td>
                                        <td className="max-w-sm px-5 py-4 text-xs leading-5 text-gray-600" title={event.user_agent || ''}>
                                            {event.user_agent ? truncateText(event.user_agent) : 'No user-agent detail recorded'}
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" className="px-6 py-14 text-center text-gray-500">
                                        <CheckCircle className="mx-auto h-11 w-11 text-emerald-400" />
                                        <p className="mt-3 text-base font-semibold text-gray-800">No threat events recorded.</p>
                                        <p className="mt-1 text-sm">The platform telemetry stream has no events to investigate yet.</p>
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
