import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, useForm, usePage } from '@inertiajs/react';
import { ArrowLeft, CheckCircle2, LockKeyhole, MailWarning, MapPin, ShieldCheck, UserRound } from 'lucide-react';

const formatDate = (value) => value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'long',
        timeStyle: 'short',
    }).format(new Date(value))
    : 'Unknown';

const booleanResult = (value) => {
    if (value === null || value === undefined) return 'Unknown';
    return value ? 'Pass' : 'Fail';
};

export default function ThreatReviewShow({ auth, threat }) {
    const { flash = {} } = usePage().props;
    const { patch, processing } = useForm({});

    const markReviewed = () => {
        patch(route('company.threats.review', threat.id), {
            preserveScroll: true,
        });
    };

    return (
        <AuthenticatedLayout
            header={(
                <div>
                    <p className="text-sm font-medium text-indigo-600">
                        {auth.portal.company?.name} · Company Security
                    </p>
                    <h1 className="text-xl font-semibold leading-tight text-gray-800">
                        Threat Detail
                    </h1>
                </div>
            )}
        >
            <Head title="Company Threat Detail" />

            <div className="py-10">
                <div className="mx-auto max-w-5xl space-y-6 px-4 sm:px-6 lg:px-8">
                    <Link
                        href={route('company.threats.index')}
                        className="inline-flex items-center text-sm font-semibold text-indigo-600 hover:text-indigo-800"
                    >
                        <ArrowLeft className="mr-2 h-4 w-4" />
                        Back to Threat Review
                    </Link>

                    {flash.success && (
                        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
                            {flash.success}
                        </div>
                    )}

                    <section className="overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm">
                        <div className="flex flex-col gap-5 border-b border-gray-200 bg-slate-900 p-7 text-white sm:flex-row sm:items-start sm:justify-between">
                            <div className="flex min-w-0 gap-4">
                                <div className="shrink-0 rounded-xl bg-red-500/15 p-3">
                                    <MailWarning className="h-7 w-7 text-red-300" />
                                </div>
                                <div className="min-w-0">
                                    <p className="text-xs font-semibold uppercase tracking-widest text-slate-300">
                                        {threat.threat_category || threat.verdict || 'Email threat'}
                                    </p>
                                    <h2 className="mt-2 break-words text-2xl font-bold">
                                        {threat.subject || 'No subject'}
                                    </h2>
                                    <p className="mt-2 break-all text-sm text-slate-300">
                                        From {threat.sender || 'Unknown sender'}
                                    </p>
                                </div>
                            </div>
                            <span className={`inline-flex self-start rounded-full px-3 py-1.5 text-xs font-bold uppercase ${threat.severity === 'critical' ? 'bg-red-500 text-white' : 'bg-orange-400 text-slate-950'}`}>
                                {threat.severity} {threat.risk_score !== null ? `· ${threat.risk_score}` : ''}
                            </span>
                        </div>

                        <div className="grid gap-6 p-7 md:grid-cols-2">
                            <div className="rounded-xl bg-gray-50 p-5">
                                <div className="flex items-center gap-2 text-sm font-semibold text-gray-900">
                                    <UserRound className="h-4 w-4 text-indigo-600" /> Employee
                                </div>
                                <p className="mt-3 text-sm font-semibold text-gray-900">{threat.employee.name}</p>
                                <p className="mt-1 text-sm text-gray-600">{threat.employee.email}</p>
                            </div>
                            <div className="rounded-xl bg-gray-50 p-5">
                                <div className="flex items-center gap-2 text-sm font-semibold text-gray-900">
                                    <ShieldCheck className="h-4 w-4 text-indigo-600" /> Detection
                                </div>
                                <dl className="mt-3 space-y-2 text-sm">
                                    <div className="flex justify-between gap-4">
                                        <dt className="text-gray-500">Verdict</dt>
                                        <dd className="font-semibold text-gray-900">{threat.verdict || 'Threat detected'}</dd>
                                    </div>
                                    <div className="flex justify-between gap-4">
                                        <dt className="text-gray-500">Scanned</dt>
                                        <dd className="text-right font-semibold text-gray-900">{formatDate(threat.scanned_at)}</dd>
                                    </div>
                                    <div className="flex justify-between gap-4">
                                        <dt className="text-gray-500">Quarantined</dt>
                                        <dd className="inline-flex items-center font-semibold text-gray-900">
                                            {threat.is_quarantined && <LockKeyhole className="mr-1.5 h-4 w-4 text-indigo-600" />}
                                            {threat.is_quarantined ? 'Yes' : 'No'}
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>

                        <div className="border-t border-gray-200 p-7">
                            <h3 className="text-base font-semibold text-gray-900">Scanner reasoning</h3>
                            <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-gray-700">
                                {threat.reasoning || 'No scanner reasoning is available for this detection.'}
                            </p>
                            <p className="mt-4 rounded-lg border border-blue-100 bg-blue-50 px-4 py-3 text-xs leading-5 text-blue-800">
                                This review intentionally excludes the full email body, snippets, attachments, and mailbox content.
                            </p>
                        </div>

                        {threat.origin && (
                            <div className="border-t border-gray-200 p-7">
                                <div className="flex items-center gap-2">
                                    <MapPin className="h-5 w-5 text-indigo-600" />
                                    <h3 className="text-base font-semibold text-gray-900">Origin indicators</h3>
                                </div>
                                <dl className="mt-4 grid gap-4 text-sm sm:grid-cols-2">
                                    <div><dt className="text-gray-500">Originating IP</dt><dd className="mt-1 font-semibold text-gray-900">{threat.origin.originating_ip || 'Unknown'}</dd></div>
                                    <div><dt className="text-gray-500">Location</dt><dd className="mt-1 font-semibold text-gray-900">{[threat.origin.location?.city, threat.origin.location?.country].filter(Boolean).join(', ') || 'Unknown'}</dd></div>
                                    <div><dt className="text-gray-500">Provider / organization</dt><dd className="mt-1 font-semibold text-gray-900">{threat.origin.provider_name || threat.origin.organization || 'Unknown'}</dd></div>
                                    <div><dt className="text-gray-500">SPF / DKIM / alignment</dt><dd className="mt-1 font-semibold text-gray-900">{booleanResult(threat.origin.authentication?.spf_pass)} / {booleanResult(threat.origin.authentication?.dkim_pass)} / {booleanResult(threat.origin.authentication?.domain_alignment_pass)}</dd></div>
                                </dl>
                                {threat.origin.origin_note && <p className="mt-4 text-sm text-gray-600">{threat.origin.origin_note}</p>}
                            </div>
                        )}

                        <div className="flex flex-col gap-4 border-t border-gray-200 bg-gray-50 p-7 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                                <p className="text-sm font-semibold text-gray-900">
                                    {threat.reviewed_at ? 'Reviewed' : 'Awaiting review'}
                                </p>
                                <p className="mt-1 text-xs text-gray-500">
                                    {threat.reviewed_at
                                        ? `${formatDate(threat.reviewed_at)}${threat.reviewed_by ? ` by ${threat.reviewed_by}` : ''}`
                                        : 'Acknowledging this event does not change its verdict, risk score, or quarantine state.'}
                                </p>
                            </div>
                            {!threat.reviewed_at && (
                                <button
                                    type="button"
                                    onClick={markReviewed}
                                    disabled={processing}
                                    className="inline-flex items-center justify-center rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                                >
                                    <CheckCircle2 className="mr-2 h-4 w-4" />
                                    {processing ? 'Saving…' : 'Mark Reviewed'}
                                </button>
                            )}
                        </div>
                    </section>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
