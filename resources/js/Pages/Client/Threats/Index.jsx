import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, router } from '@inertiajs/react';
import { AlertTriangle, Clock3, Eye, Filter, LockKeyhole, ShieldAlert } from 'lucide-react';
import { useState } from 'react';

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Unknown';

const riskStyle = (severity) => severity === 'critical'
    ? 'bg-red-100 text-red-800 ring-red-200'
    : 'bg-orange-100 text-orange-800 ring-orange-200';

const paginationLabel = (label) => label
    .replace('&laquo;', '')
    .replace('&raquo;', '')
    .trim();

const summaryCards = [
    { key: 'critical', label: 'Critical', icon: AlertTriangle, color: 'bg-red-50 text-red-700' },
    { key: 'high', label: 'High', icon: ShieldAlert, color: 'bg-orange-50 text-orange-700' },
    { key: 'unreviewed', label: 'Unreviewed', icon: Clock3, color: 'bg-amber-50 text-amber-700' },
    { key: 'quarantined', label: 'Quarantined', icon: LockKeyhole, color: 'bg-indigo-50 text-indigo-700' },
];

export default function ThreatReviewIndex({ auth, threats, filters, summary = {} }) {
    const [risk, setRisk] = useState(filters.risk || 'all');
    const [review, setReview] = useState(filters.review || 'all');

    const applyFilters = (event) => {
        event.preventDefault();
        router.get(
            route('company.threats.index'),
            { risk, review },
            { preserveScroll: true, preserveState: true, replace: true },
        );
    };

    return (
        <AuthenticatedLayout
            header={(
                <div>
                    <p className="text-sm font-medium text-indigo-600">
                        {auth.portal.company?.name} · Company Security
                    </p>
                    <h1 className="text-xl font-semibold leading-tight text-gray-800">
                        Threat Review
                    </h1>
                </div>
            )}
        >
            <Head title="Company Threat Review" />

            <div className="py-10">
                <div className="mx-auto max-w-7xl space-y-6 px-4 sm:px-6 lg:px-8">
                    <section className="rounded-2xl border border-red-100 bg-gradient-to-r from-red-950 to-slate-900 p-7 text-white shadow-lg">
                        <div className="flex items-start gap-4">
                            <div className="rounded-xl bg-white/10 p-3">
                                <AlertTriangle className="h-7 w-7 text-red-200" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold">High / Critical email detections</h2>
                                <p className="mt-2 max-w-3xl text-sm leading-6 text-red-100/90">
                                    Review security metadata and scanner reasoning for employees in your company. Full email bodies, attachments, and mailbox contents are not available here.
                                </p>
                            </div>
                        </div>
                    </section>

                    <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                        {summaryCards.map((card) => {
                            const Icon = card.icon;

                            return (
                                <div key={card.key} className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
                                    <div className={`inline-flex rounded-xl p-2.5 ${card.color}`}>
                                        <Icon className="h-5 w-5" />
                                    </div>
                                    <p className="mt-4 text-3xl font-bold text-gray-900">{summary[card.key] ?? 0}</p>
                                    <p className="mt-1 text-sm font-semibold text-gray-700">{card.label}</p>
                                </div>
                            );
                        })}
                    </section>

                    <form
                        onSubmit={applyFilters}
                        className="flex flex-col gap-4 rounded-2xl border border-gray-200 bg-white p-5 shadow-sm sm:flex-row sm:items-end"
                    >
                        <div className="flex-1">
                            <label htmlFor="risk-filter" className="text-sm font-semibold text-gray-700">
                                Risk
                            </label>
                            <select
                                id="risk-filter"
                                value={risk}
                                onChange={(event) => setRisk(event.target.value)}
                                className="mt-2 block w-full rounded-lg border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                            >
                                <option value="all">All high / critical</option>
                                <option value="critical">Critical only</option>
                                <option value="high">High only</option>
                            </select>
                        </div>
                        <div className="flex-1">
                            <label htmlFor="review-filter" className="text-sm font-semibold text-gray-700">
                                Review status
                            </label>
                            <select
                                id="review-filter"
                                value={review}
                                onChange={(event) => setReview(event.target.value)}
                                className="mt-2 block w-full rounded-lg border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                            >
                                <option value="all">All</option>
                                <option value="unreviewed">Unreviewed</option>
                                <option value="reviewed">Reviewed</option>
                            </select>
                        </div>
                        <button
                            type="submit"
                            className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-indigo-700"
                        >
                            <Filter className="mr-2 h-4 w-4" />
                            Apply filters
                        </button>
                    </form>

                    <section className="overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm">
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        {['Employee', 'Email detection', 'Risk', 'Quarantine', 'Review', 'Detected', ''].map((heading) => (
                                            <th key={heading} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">
                                                {heading}
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-100">
                                    {threats.data.map((threat) => (
                                        <tr key={threat.id} className="hover:bg-gray-50/70">
                                            <td className="px-5 py-4">
                                                <p className="text-sm font-semibold text-gray-900">{threat.employee.name}</p>
                                                <p className="mt-1 text-xs text-gray-500">{threat.employee.email}</p>
                                            </td>
                                            <td className="max-w-md px-5 py-4">
                                                <p className="truncate text-sm font-semibold text-gray-900">{threat.subject || 'No subject'}</p>
                                                <p className="mt-1 truncate text-xs text-gray-500">From {threat.sender || 'Unknown sender'}</p>
                                                <p className="mt-1 text-xs font-medium text-gray-600">
                                                    {threat.threat_category || threat.verdict || 'Threat detected'}
                                                </p>
                                            </td>
                                            <td className="px-5 py-4">
                                                <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-bold uppercase ring-1 ring-inset ${riskStyle(threat.severity)}`}>
                                                    {threat.severity}
                                                </span>
                                                {threat.risk_score !== null && (
                                                    <p className="mt-2 text-xs text-gray-500">Score {threat.risk_score}</p>
                                                )}
                                            </td>
                                            <td className="px-5 py-4 text-sm text-gray-700">
                                                {threat.is_quarantined ? (
                                                    <span className="inline-flex items-center font-medium text-indigo-700">
                                                        <LockKeyhole className="mr-1.5 h-4 w-4" /> Yes
                                                    </span>
                                                ) : 'No'}
                                            </td>
                                            <td className="px-5 py-4">
                                                <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${threat.reviewed_at ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}`}>
                                                    {threat.reviewed_at ? 'Reviewed' : 'Unreviewed'}
                                                </span>
                                            </td>
                                            <td className="whitespace-nowrap px-5 py-4 text-xs text-gray-500">
                                                {formatDate(threat.scanned_at)}
                                            </td>
                                            <td className="px-5 py-4 text-right">
                                                <Link
                                                    href={route('company.threats.show', threat.id)}
                                                    className="inline-flex items-center rounded-lg border border-gray-300 px-3 py-2 text-sm font-semibold text-gray-700 transition hover:border-indigo-300 hover:text-indigo-700"
                                                >
                                                    <Eye className="mr-1.5 h-4 w-4" />
                                                    Review
                                                </Link>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {threats.data.length === 0 && (
                            <div className="px-6 py-16 text-center">
                                <AlertTriangle className="mx-auto h-10 w-10 text-gray-300" />
                                <h3 className="mt-4 text-base font-semibold text-gray-900">No matching threats</h3>
                                <p className="mt-2 text-sm text-gray-500">
                                    No high or critical company email detections match the selected filters.
                                </p>
                            </div>
                        )}

                        {threats.links.length > 3 && (
                            <div className="flex flex-wrap gap-2 border-t border-gray-200 px-5 py-4">
                                {threats.links.map((link) => (
                                    link.url ? (
                                        <Link
                                            key={link.label}
                                            href={link.url}
                                            preserveScroll
                                            className={`rounded-md px-3 py-1.5 text-sm ${link.active ? 'bg-indigo-600 text-white' : 'border border-gray-300 text-gray-700 hover:bg-gray-50'}`}
                                        >
                                            {paginationLabel(link.label)}
                                        </Link>
                                    ) : (
                                        <span key={link.label} className="rounded-md px-3 py-1.5 text-sm text-gray-400">
                                            {paginationLabel(link.label)}
                                        </span>
                                    )
                                ))}
                            </div>
                        )}
                    </section>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
