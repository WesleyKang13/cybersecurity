import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, router, usePage } from '@inertiajs/react';
import {
    ArrowLeft,
    CheckCircle2,
    Globe2,
    LoaderCircle,
    ShieldAlert,
    Undo2,
} from 'lucide-react';
import { useState } from 'react';

const formatBlockedAt = (timestamp) => {
    if (!timestamp) {
        return 'Unknown';
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return 'Unknown';
    }

    return date.toLocaleString();
};

export default function BlockedIpsIndex({ auth, blockedIps = [] }) {
    const { flash } = usePage().props;
    const [unblockingId, setUnblockingId] = useState(null);

    const globalBlockedCount = blockedIps.filter((blockedIp) => blockedIp.is_global).length;
    const domainBlockedCount = blockedIps.length - globalBlockedCount;

    const unblockIp = (blockedIp) => {
        const confirmationMessage = blockedIp.is_global
            ? `Remove the global block for ${blockedIp.ip}?`
            : `Remove the block for ${blockedIp.ip} on ${blockedIp.target_domain || 'this domain'}?`;

        if (!window.confirm(confirmationMessage)) {
            return;
        }

        setUnblockingId(blockedIp.id);

        router.delete(route('admin.blocked-ips.destroy', blockedIp.id), {
            preserveScroll: true,
            onFinish: () => setUnblockingId(null),
        });
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="text-xl font-semibold leading-tight text-gray-800">Blocked IPs</h2>}
        >
            <Head title="Blocked IPs" />

            <div className="py-10">
                <div className="mx-auto w-full max-w-7xl space-y-6 px-4 sm:px-6 lg:px-8">
                    <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm">
                        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                            <div className="space-y-3">
                                <div className="inline-flex items-center gap-2 rounded-full border border-red-200 bg-red-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-red-700">
                                    <ShieldAlert className="h-4 w-4" />
                                    Active IP Blocks
                                </div>
                                <div>
                                    <h1 className="text-3xl font-black tracking-tight text-gray-900">
                                        Blocked IPs Management
                                    </h1>
                                    <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-600">
                                        Review auto-banned and manually blocked addresses, then remove active blocks when traffic is no longer hostile.
                                    </p>
                                </div>
                            </div>

                            <Link
                                href={route('platform.dashboard')}
                                className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-4 py-2.5 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-100"
                            >
                                <ArrowLeft className="mr-2 h-4 w-4" />
                                Back to Security Overview
                            </Link>
                        </div>

                        <div className="mt-6 grid gap-4 sm:grid-cols-3">
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 p-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Active Blocks</p>
                                <p className="mt-3 text-3xl font-black text-gray-900">{blockedIps.length}</p>
                            </div>
                            <div className="rounded-2xl border border-red-200 bg-red-50 p-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-red-700">Global Scope</p>
                                <p className="mt-3 text-3xl font-black text-red-900">{globalBlockedCount}</p>
                            </div>
                            <div className="rounded-2xl border border-cyan-200 bg-cyan-50 p-4">
                                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-700">Domain Scope</p>
                                <p className="mt-3 text-3xl font-black text-cyan-900">{domainBlockedCount}</p>
                            </div>
                        </div>
                    </section>

                    {flash?.success && (
                        <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-sm">
                            <CheckCircle2 className="h-5 w-5 shrink-0" />
                            <span>{flash.success}</span>
                        </div>
                    )}

                    {flash?.error && (
                        <div className="flex items-center gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 shadow-sm">
                            <ShieldAlert className="h-5 w-5 shrink-0" />
                            <span>{flash.error}</span>
                        </div>
                    )}

                    <section className="rounded-3xl border border-gray-200 bg-white shadow-sm">
                        {blockedIps.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">IP Address</th>
                                            <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Scope</th>
                                            <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Target Domain</th>
                                            <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Reason</th>
                                            <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Blocked At</th>
                                            <th className="px-6 py-4 text-right text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-200 bg-white">
                                        {blockedIps.map((blockedIp) => {
                                            const isUnblocking = unblockingId === blockedIp.id;

                                            return (
                                                <tr key={blockedIp.id} className="align-top transition hover:bg-gray-50">
                                                    <td className="px-6 py-4">
                                                        <span className="font-mono text-sm font-semibold text-gray-900">
                                                            {blockedIp.ip}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <span
                                                            className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide ${
                                                                blockedIp.is_global
                                                                    ? 'border-red-200 bg-red-100 text-red-800'
                                                                    : 'border-cyan-200 bg-cyan-100 text-cyan-800'
                                                            }`}
                                                        >
                                                            {blockedIp.is_global ? 'Global' : 'Domain'}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 text-sm text-gray-700">
                                                        {blockedIp.is_global ? (
                                                            <span className="inline-flex items-center gap-2 text-gray-600">
                                                                <Globe2 className="h-4 w-4" />
                                                                All monitored domains
                                                            </span>
                                                        ) : (
                                                            blockedIp.target_domain || 'Unknown domain'
                                                        )}
                                                    </td>
                                                    <td className="px-6 py-4 text-sm leading-6 text-gray-600">
                                                        {blockedIp.reason || 'No reason supplied.'}
                                                    </td>
                                                    <td className="px-6 py-4 text-sm text-gray-500">
                                                        {formatBlockedAt(blockedIp.blocked_at)}
                                                    </td>
                                                    <td className="px-6 py-4 text-right">
                                                        <button
                                                            type="button"
                                                            onClick={() => unblockIp(blockedIp)}
                                                            disabled={isUnblocking}
                                                            className="inline-flex items-center rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                                                        >
                                                            {isUnblocking ? (
                                                                <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                                                            ) : (
                                                                <Undo2 className="mr-2 h-4 w-4" />
                                                            )}
                                                            Unblock
                                                        </button>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="px-6 py-16 text-center">
                                <ShieldAlert className="mx-auto h-12 w-12 text-gray-300" />
                                <h3 className="mt-4 text-lg font-bold text-gray-900">No blocked IPs right now</h3>
                                <p className="mt-2 text-sm text-gray-500">
                                    Auto-ban and manual block lists are currently empty. New active blocks will appear here as soon as they are created.
                                </p>
                            </div>
                        )}
                    </section>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
