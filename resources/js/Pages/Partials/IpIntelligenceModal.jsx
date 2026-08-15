import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import { AlertCircle, LoaderCircle } from 'lucide-react';

export default function IpIntelligenceModal({ state, onClose }) {
    const { show, loading, ip, data, error } = state;

    return (
        <Modal show={show} onClose={onClose} maxWidth="md">
            <div className="bg-white p-6 dark:bg-gray-800">
                <div className="space-y-2">
                    <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">IP Intelligence</h2>
                    <p className="font-mono text-sm text-gray-500 dark:text-gray-400">{ip || 'Unknown IP'}</p>
                </div>

                {loading ? (
                    <div className="mt-6 flex items-center gap-3 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 text-sm text-gray-700 dark:border-gray-700 dark:bg-gray-900/60 dark:text-gray-200">
                        <LoaderCircle className="h-5 w-5 animate-spin" />
                        <span>Loading IP intelligence...</span>
                    </div>
                ) : error ? (
                    <div className="mt-6 flex items-center gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-4 text-sm text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-100">
                        <AlertCircle className="h-5 w-5 shrink-0" />
                        <span>{error}</span>
                    </div>
                ) : data ? (
                    <div className="mt-6 space-y-4">
                        <div className="flex flex-wrap gap-2">
                            {data.proxy && (
                                <span className="inline-flex rounded-full border border-red-200 bg-red-50 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-red-700 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200">
                                    Proxy / VPN
                                </span>
                            )}
                            {data.hosting && (
                                <span className="inline-flex rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200">
                                    Hosting Provider
                                </span>
                            )}
                            {data.mobile && (
                                <span className="inline-flex rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-cyan-700 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200">
                                    Cellular Network
                                </span>
                            )}
                        </div>

                        <div className="grid gap-3 sm:grid-cols-2">
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">ISP</p>
                                <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {data.isp || 'Unknown'}
                                </p>
                            </div>
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Organization</p>
                                <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {data.org || 'Unknown'}
                                </p>
                            </div>
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Region / City</p>
                                <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {[data.regionName, data.city].filter(Boolean).join(', ') || 'Unknown'}
                                </p>
                            </div>
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Country</p>
                                <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {data.country || 'Unknown'}
                                </p>
                            </div>
                        </div>

                        <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">ASN</p>
                            <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                {data.as || 'Unknown'}
                            </p>
                        </div>
                    </div>
                ) : null}

                <div className="mt-6 flex justify-end">
                    <SecondaryButton onClick={onClose}>Close</SecondaryButton>
                </div>
            </div>
        </Modal>
    );
}
