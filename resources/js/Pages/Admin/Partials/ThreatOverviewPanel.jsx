import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import { CheckCircle, Eye, ShieldAlert } from 'lucide-react';
import { useMemo, useState } from 'react';

const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info', 'unclassified'];

const CANONICAL_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_STYLES = {
    critical: 'bg-red-100 text-red-800',
    high: 'bg-orange-100 text-orange-800',
    medium: 'bg-amber-100 text-amber-800',
    low: 'bg-blue-100 text-blue-800',
    info: 'bg-cyan-100 text-cyan-800',
    unclassified: 'bg-gray-100 text-gray-700',
};

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Unknown';

const formatLabel = (value, fallback) => String(value || '')
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ') || fallback;

const normalizedSeverity = (value) => {
    const normalized = String(value || '').toLowerCase();

    return CANONICAL_SEVERITIES.includes(normalized) ? normalized : 'unclassified';
};

const severityLabel = (value) => formatLabel(normalizedSeverity(value), 'Unclassified');

const eventTypeLabel = (value) => formatLabel(value, 'Generic Threat');

const metadataText = (metadata) => {
    if (!metadata || typeof metadata !== 'object' || Object.keys(metadata).length === 0) {
        return null;
    }

    return JSON.stringify(metadata, null, 2);
};

const failedLoginMetadata = (event) => (
    event?.event_type === 'failed_login'
    && event.metadata
    && typeof event.metadata === 'object'
    && !Array.isArray(event.metadata)
        ? event.metadata
        : null
);

const failedLoginAccountContext = (event) => {
    const metadata = failedLoginMetadata(event);

    if (!metadata) {
        return [];
    }

    const context = [];

    if (typeof metadata.account_exists === 'boolean') {
        context.push({ key: 'account-exists', label: 'Account exists', value: metadata.account_exists ? 'Yes' : 'No' });
    }

    if (typeof metadata.target_role === 'string' && metadata.target_role.trim()) {
        context.push({ key: 'target-role', label: 'Role', value: formatLabel(metadata.target_role, 'Unknown') });
    }

    if (typeof metadata.attempted_identifier_masked === 'string' && metadata.attempted_identifier_masked.trim()) {
        context.push({ key: 'attempted-account', label: 'Attempted account', value: metadata.attempted_identifier_masked });
    }

    if (Number.isInteger(metadata.attempt_count) && metadata.attempt_count >= 1) {
        context.push({ key: 'attempt-count', label: 'Attempt count', value: String(metadata.attempt_count) });
    }

    return context;
};

function DetailItem({ label, children, className = '' }) {
    return (
        <div className={`rounded-xl border border-gray-200 bg-gray-50 px-4 py-3 ${className}`}>
            <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</dt>
            <dd className="mt-1 break-words text-sm text-gray-900">{children}</dd>
        </div>
    );
}

export default function ThreatOverviewPanel({ events = [], onInspectIp }) {
    const [severityFilter, setSeverityFilter] = useState('all');
    const [selectedEvent, setSelectedEvent] = useState(null);
    const selectedFailedLoginMetadata = failedLoginMetadata(selectedEvent);
    const selectedFailedLoginAccountContext = failedLoginAccountContext(selectedEvent);

    const filteredEvents = useMemo(() => {
        if (severityFilter === 'all') {
            return events;
        }

        return events.filter((event) => normalizedSeverity(event.severity) === severityFilter);
    }, [events, severityFilter]);

    const inspectIp = (ipAddress) => {
        setSelectedEvent(null);
        onInspectIp(ipAddress);
    };

    return (
        <div className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
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

                <label className="text-sm font-semibold text-gray-700">
                    Severity
                    <select
                        value={severityFilter}
                        onChange={(event) => setSeverityFilter(event.target.value)}
                        className="ml-3 rounded-lg border-gray-300 py-2 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                    >
                        {SEVERITY_FILTERS.map((severity) => (
                            <option key={severity} value={severity}>{formatLabel(severity, 'All')}</option>
                        ))}
                    </select>
                </label>
            </div>

            <section className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                {['Threat Type', 'Severity', 'Detected / Source', 'Attacker', 'Application / Target', 'Reason', 'Action Taken', 'Details'].map((heading) => (
                                    <th key={heading} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">
                                        {heading}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 bg-white">
                            {filteredEvents.length > 0 ? (
                                filteredEvents.map((event) => {
                                    const severity = normalizedSeverity(event.severity);

                                    return (
                                        <tr key={event.id} className="align-top transition hover:bg-gray-50/70">
                                            <td className="px-4 py-4 text-sm font-semibold text-gray-900">
                                                {eventTypeLabel(event.event_type)}
                                            </td>
                                            <td className="px-4 py-4">
                                                <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${SEVERITY_STYLES[severity] || SEVERITY_STYLES.unclassified}`}>
                                                    {severityLabel(event.severity)}
                                                </span>
                                            </td>
                                            <td className="whitespace-nowrap px-4 py-4 text-xs text-gray-600">
                                                {formatDate(event.detected_at)}
                                                <p className="mt-1 text-purple-700">{event.threat_source || 'Telemetry'}</p>
                                            </td>
                                            <td className="px-4 py-4">
                                                <button
                                                    type="button"
                                                    onClick={() => onInspectIp(event.attacker_ip)}
                                                    className="font-mono text-xs font-semibold text-blue-600 hover:underline"
                                                >
                                                    {event.attacker_ip}
                                                </button>
                                                <p className="mt-1 text-xs text-gray-500">{event.country || 'Unknown location'}</p>
                                            </td>
                                            <td className="px-4 py-4">
                                                <p className="text-sm font-semibold text-gray-900">
                                                    {event.monitored_domain?.domain || 'Unknown application'}
                                                </p>
                                                <p className="mt-1 max-w-xs truncate font-mono text-xs text-gray-500" title={event.path_targeted || ''}>
                                                    {event.path_targeted || 'No targeted path recorded'}
                                                </p>
                                            </td>
                                            <td className="max-w-xs px-4 py-4 text-xs leading-5 text-gray-600">
                                                {event.reason || 'No reason provided'}
                                            </td>
                                            <td className="px-4 py-4">
                                                <span className="inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold uppercase text-emerald-700">
                                                    {event.action_taken || 'Recorded'}
                                                </span>
                                            </td>
                                            <td className="px-4 py-4">
                                                <button
                                                    type="button"
                                                    onClick={() => setSelectedEvent(event)}
                                                    className="inline-flex items-center text-xs font-semibold text-indigo-600 hover:text-indigo-800"
                                                >
                                                    <Eye className="mr-1.5 h-4 w-4" /> View
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })
                            ) : (
                                <tr>
                                    <td colSpan="8" className="px-6 py-14 text-center text-gray-500">
                                        <CheckCircle className="mx-auto h-11 w-11 text-emerald-400" />
                                        <p className="mt-3 text-base font-semibold text-gray-800">No matching threat events.</p>
                                        <p className="mt-1 text-sm">No events match the selected severity.</p>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </section>

            <Modal show={selectedEvent !== null} onClose={() => setSelectedEvent(null)} maxWidth="3xl">
                {selectedEvent ? (
                    <div className="max-h-[85vh] overflow-y-auto p-6">
                        <div className="flex items-start justify-between gap-4 border-b border-gray-200 pb-4">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">Threat detail</p>
                                <h4 className="mt-1 text-2xl font-bold text-gray-900">{eventTypeLabel(selectedEvent.event_type)}</h4>
                            </div>
                            <span className={`inline-flex rounded-full px-3 py-1.5 text-sm font-semibold ${SEVERITY_STYLES[normalizedSeverity(selectedEvent.severity)] || SEVERITY_STYLES.unclassified}`}>
                                {severityLabel(selectedEvent.severity)}
                            </span>
                        </div>

                        <dl className="mt-5 grid gap-3 sm:grid-cols-2">
                            <DetailItem label="Threat Type">{eventTypeLabel(selectedEvent.event_type)}</DetailItem>
                            <DetailItem label="Severity">{severityLabel(selectedEvent.severity)}</DetailItem>
                            <DetailItem label="Reason" className="sm:col-span-2">{selectedEvent.reason || 'No reason provided'}</DetailItem>
                            <DetailItem label="Action Taken">{selectedEvent.action_taken || 'Recorded'}</DetailItem>
                            <DetailItem label="Source">{selectedEvent.threat_source || 'Telemetry'}</DetailItem>
                            <DetailItem label="Attacker IP">
                                <button
                                    type="button"
                                    onClick={() => inspectIp(selectedEvent.attacker_ip)}
                                    className="font-mono font-semibold text-blue-600 hover:underline"
                                >
                                    {selectedEvent.attacker_ip}
                                </button>
                                <span className="ml-2 text-xs text-gray-500">{selectedEvent.country || 'Unknown country'}</span>
                            </DetailItem>
                            <DetailItem label="Application / Domain">{selectedEvent.monitored_domain?.domain || 'Unknown application'}</DetailItem>
                            <DetailItem label="Targeted Path" className="sm:col-span-2">
                                <span className="font-mono">
                                    {typeof selectedFailedLoginMetadata?.http_method === 'string' ? `${selectedFailedLoginMetadata.http_method.toUpperCase()} ` : ''}
                                    {selectedEvent.path_targeted || 'No targeted path recorded'}
                                </span>
                                {typeof selectedFailedLoginMetadata?.route_name === 'string' && selectedFailedLoginMetadata.route_name.trim() ? (
                                    <span className="mt-1 block text-xs text-gray-500">Route: {selectedFailedLoginMetadata.route_name}</span>
                                ) : null}
                            </DetailItem>
                            <DetailItem label="Detected At">{formatDate(selectedEvent.detected_at)}</DetailItem>
                            <DetailItem label="User Agent">{selectedEvent.user_agent || 'No user-agent detail recorded'}</DetailItem>
                            {selectedFailedLoginAccountContext.length > 0 ? (
                                <DetailItem label="Account Target" className="sm:col-span-2">
                                    <dl className="mt-2 grid gap-3 sm:grid-cols-2">
                                        {selectedFailedLoginAccountContext.map((item) => (
                                            <div key={item.key} className="rounded-lg border border-gray-200 bg-white px-3 py-2">
                                                <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">{item.label}</dt>
                                                <dd className="mt-1 break-words text-sm text-gray-900">{item.value}</dd>
                                            </div>
                                        ))}
                                    </dl>
                                </DetailItem>
                            ) : null}
                            {metadataText(selectedEvent.metadata) ? (
                                <DetailItem label="Sanitized Metadata" className="sm:col-span-2">
                                    <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-5">{metadataText(selectedEvent.metadata)}</pre>
                                </DetailItem>
                            ) : null}
                        </dl>

                        <div className="mt-6 flex justify-end">
                            <SecondaryButton onClick={() => setSelectedEvent(null)}>Close</SecondaryButton>
                        </div>
                    </div>
                ) : null}
            </Modal>
        </div>
    );
}
