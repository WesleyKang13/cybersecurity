import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link } from '@inertiajs/react';
import {
    AlertTriangle,
    ArrowRight,
    Building2,
    CheckCircle2,
    Clock3,
    LockKeyhole,
    Mail,
    ShieldAlert,
    ShieldCheck,
    Smartphone,
    UserRound,
} from 'lucide-react';

const portalCards = [
    {
        title: 'Email Security',
        description: 'Review your connected mailbox, security scans, and personal email alerts.',
        route: 'dashboard',
        icon: Mail,
        color: 'text-blue-600 bg-blue-50',
    },
    {
        title: 'SMS Scanner',
        description: 'Analyze suspicious text messages using the existing SMS security scanner.',
        route: 'sms.index',
        icon: Smartphone,
        color: 'text-indigo-600 bg-indigo-50',
    },
    {
        title: 'Profile',
        description: 'Manage your own account information and password.',
        route: 'profile.edit',
        icon: UserRound,
        color: 'text-emerald-600 bg-emerald-50',
    },
];

const summaryCards = [
    {
        key: 'critical',
        label: 'Critical',
        helper: 'Critical company detections',
        icon: AlertTriangle,
        color: 'bg-red-50 text-red-700',
    },
    {
        key: 'high',
        label: 'High',
        helper: 'High-risk company detections',
        icon: ShieldAlert,
        color: 'bg-orange-50 text-orange-700',
    },
    {
        key: 'unreviewed',
        label: 'Unreviewed',
        helper: 'Threats not yet acknowledged',
        icon: Clock3,
        color: 'bg-amber-50 text-amber-700',
    },
    {
        key: 'quarantined',
        label: 'Quarantined',
        helper: 'Threats already quarantined',
        icon: LockKeyhole,
        color: 'bg-indigo-50 text-indigo-700',
    },
    {
        key: 'recent',
        label: 'Last 7 days',
        helper: 'Recently detected threats',
        icon: CheckCircle2,
        color: 'bg-emerald-50 text-emerald-700',
    },
];

export default function ClientDashboard({ auth, threatSummary = {} }) {
    const companyName = auth.portal.company?.name;

    return (
        <AuthenticatedLayout
            header={(
                <div>
                    <p className="text-sm font-medium text-indigo-600">Security Portal</p>
                    <h2 className="text-xl font-semibold leading-tight text-gray-800">
                        {companyName}
                    </h2>
                </div>
            )}
        >
            <Head title="Client Security Portal" />

            <div className="py-12">
                <div className="mx-auto max-w-6xl space-y-8 px-4 sm:px-6 lg:px-8">
                    <section className="overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 to-indigo-900 p-8 text-white shadow-xl">
                        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
                            <div className="max-w-2xl">
                                <div className="mb-4 inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-indigo-100">
                                    <ShieldCheck className="h-4 w-4" />
                                    Client Company Portal
                                </div>
                                <h1 className="text-3xl font-bold tracking-tight">
                                    {companyName}
                                </h1>
                                <p className="mt-3 text-sm leading-6 text-slate-200">
                                    Access your own email security, SMS analysis, and account settings. Company administration features will be introduced in a later phase.
                                </p>
                            </div>
                            <Building2 className="h-20 w-20 text-indigo-300/70" />
                        </div>
                    </section>

                    <section className="space-y-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                            <div>
                                <p className="text-sm font-semibold uppercase tracking-wider text-indigo-600">
                                    Company Security
                                </p>
                                <h2 className="mt-1 text-2xl font-bold text-gray-900">
                                    Email threat review
                                </h2>
                                <p className="mt-1 text-sm text-gray-600">
                                    High and critical detections only. Employee message content is not shown.
                                </p>
                            </div>
                            <Link
                                href={route('company.threats.index')}
                                className="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
                            >
                                Open Threat Review
                                <ArrowRight className="ml-2 h-4 w-4" />
                            </Link>
                        </div>

                        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                            {summaryCards.map((card) => {
                                const Icon = card.icon;

                                return (
                                    <div key={card.key} className="rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
                                        <div className={`inline-flex rounded-xl p-2.5 ${card.color}`}>
                                            <Icon className="h-5 w-5" />
                                        </div>
                                        <p className="mt-4 text-3xl font-bold text-gray-900">
                                            {threatSummary[card.key] ?? 0}
                                        </p>
                                        <p className="mt-1 text-sm font-semibold text-gray-800">{card.label}</p>
                                        <p className="mt-1 text-xs leading-5 text-gray-500">{card.helper}</p>
                                    </div>
                                );
                            })}
                        </div>
                    </section>

                    <section className="grid gap-6 md:grid-cols-3">
                        {portalCards.map((card) => {
                            const Icon = card.icon;

                            return (
                                <Link
                                    key={card.route}
                                    href={route(card.route)}
                                    className="group rounded-2xl border border-gray-200 bg-white p-6 shadow-sm transition hover:-translate-y-0.5 hover:border-indigo-200 hover:shadow-md"
                                >
                                    <div className={`inline-flex rounded-xl p-3 ${card.color}`}>
                                        <Icon className="h-6 w-6" />
                                    </div>
                                    <h2 className="mt-5 text-lg font-semibold text-gray-900">
                                        {card.title}
                                    </h2>
                                    <p className="mt-2 text-sm leading-6 text-gray-600">
                                        {card.description}
                                    </p>
                                    <span className="mt-5 inline-flex items-center text-sm font-semibold text-indigo-600">
                                        Open
                                        <ArrowRight className="ml-2 h-4 w-4 transition group-hover:translate-x-1" />
                                    </span>
                                </Link>
                            );
                        })}
                    </section>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
