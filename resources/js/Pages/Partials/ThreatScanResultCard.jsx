import {
    AlertTriangle,
    ChevronDown,
    ChevronUp,
    ShieldAlert,
    ShieldCheck,
} from 'lucide-react';
import { useState } from 'react';

const VERDICT_STYLES = {
    MALICIOUS: {
        badge: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-500/15 dark:text-red-200 dark:border-red-500/30',
        icon: ShieldAlert,
        iconClass: 'text-red-600 dark:text-red-300',
        progress: 'bg-red-500',
        accent: 'from-red-500/10 to-red-500/0',
    },
    SUSPICIOUS: {
        badge: 'bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:border-amber-500/30',
        icon: AlertTriangle,
        iconClass: 'text-amber-600 dark:text-amber-300',
        progress: 'bg-amber-500',
        accent: 'from-amber-500/10 to-amber-500/0',
    },
    INCONCLUSIVE: {
        badge: 'bg-slate-100 text-slate-800 border-slate-200 dark:bg-slate-500/15 dark:text-slate-200 dark:border-slate-500/30',
        icon: AlertTriangle,
        iconClass: 'text-slate-600 dark:text-slate-300',
        progress: 'bg-slate-500',
        accent: 'from-slate-500/10 to-slate-500/0',
    },
    CLEAN: {
        badge: 'bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:border-emerald-500/30',
        icon: ShieldCheck,
        iconClass: 'text-emerald-600 dark:text-emerald-300',
        progress: 'bg-emerald-500',
        accent: 'from-emerald-500/10 to-emerald-500/0',
    },
};

const SEVERITY_STYLES = {
    high: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-200',
    medium: 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-200',
    low: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-200',
    clean: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-200',
};

const normalizeVerdict = (verdict) => {
    const normalized = String(verdict || 'INCONCLUSIVE').toUpperCase();

    if (normalized === 'SAFE') {
        return 'CLEAN';
    }

    return VERDICT_STYLES[normalized] ? normalized : 'INCONCLUSIVE';
};

const clampScore = (riskScore) => {
    const numericScore = Number(riskScore);

    if (Number.isNaN(numericScore)) {
        return 0;
    }

    return Math.min(100, Math.max(0, Math.round(numericScore)));
};

const formatLocation = (location) => {
    if (!location || typeof location !== 'object') {
        return 'Unknown';
    }

    return [location.city, location.country].filter(Boolean).join(', ') || 'Unknown';
};

const formatIsp = (isp) => {
    if (!isp || typeof isp !== 'object') {
        return 'Unknown';
    }

    const name = [isp.name, isp.asn].filter(Boolean).join(' • ');

    return name || 'Unknown';
};

export default function ThreatScanResultCard({ result }) {
    const [isExpanded, setIsExpanded] = useState(false);

    const safeResult = {
        verdict: 'INCONCLUSIVE',
        risk_score: 1,
        severity: 'inconclusive',
        reason: 'Analysis pending.',
        analysis_status: 'processing',
        threat_category: 'None',
        analysis_chain: [],
        origin_trace: null,
        ...result,
    };

    const verdict = normalizeVerdict(safeResult.verdict);
    const verdictStyle = VERDICT_STYLES[verdict];
    const VerdictIcon = verdictStyle.icon;
    const riskScore = clampScore(safeResult.risk_score);
    const severity = String(safeResult.severity || 'low').toLowerCase();
    const severityStyle = SEVERITY_STYLES[severity] || SEVERITY_STYLES.low;
    const analysisChain = Array.isArray(safeResult.analysis_chain) ? safeResult.analysis_chain : [];
    const originTrace = safeResult.origin_trace && typeof safeResult.origin_trace === 'object'
        ? safeResult.origin_trace
        : null;
    const hopsDetail = Array.isArray(originTrace?.hops_detail) ? originTrace.hops_detail : [];
    const showTrustedProviderBadge = Boolean(originTrace?.is_trusted_provider);
    const showProxyWarning = !showTrustedProviderBadge && Boolean(originTrace?.is_proxy_or_vpn);
    const showHostingWarning = !showTrustedProviderBadge
        && Boolean(originTrace?.is_hosting_provider_warning ?? originTrace?.is_hosting_provider);
    const trustedProviderLabel = originTrace?.provider_name || originTrace?.isp?.organization || 'Trusted Provider Infrastructure';

    return (
        <section className={`overflow-hidden rounded-2xl border border-gray-200 bg-gradient-to-br ${verdictStyle.accent} from-white to-gray-50 shadow-sm dark:border-gray-700 dark:from-gray-900 dark:to-gray-900/40`}>
            <div className="space-y-5 p-5 sm:p-6">
                <div className="grid w-full grid-cols-1 gap-4 md:grid-cols-2 md:items-start">
                    <div className="space-y-4">
                        <div className="flex flex-wrap items-center gap-3">
                            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-bold uppercase tracking-[0.2em] ${verdictStyle.badge}`}>
                                <VerdictIcon className={`h-4 w-4 ${verdictStyle.iconClass}`} />
                                {verdict}
                            </span>
                            <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${severityStyle}`}>
                                {severity}
                            </span>
                        </div>

                        <div className="space-y-2">
                            {safeResult.analysis_status && safeResult.analysis_status !== 'completed' && (
                                <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">
                                    {safeResult.analysis_status === 'retry_pending' ? 'Analysis retrying' : safeResult.analysis_status === 'processing' ? 'Analysis pending' : 'Analysis unavailable'}
                                </p>
                            )}
                            <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                Threat Category
                            </p>
                            <p className="text-base font-semibold text-gray-900 dark:text-gray-100">
                                {safeResult.threat_category || 'None'}
                            </p>
                        </div>
                    </div>

                    <div className="w-full rounded-2xl border border-gray-200 bg-white/80 p-4 dark:border-gray-700 dark:bg-gray-900/70">
                        <div className="flex items-end justify-between gap-3">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                    Risk Score
                                </p>
                                <p className="mt-2 text-3xl font-black text-gray-900 dark:text-gray-100">
                                    {riskScore}
                                    <span className="ml-1 text-sm font-semibold text-gray-500 dark:text-gray-400">/100</span>
                                </p>
                            </div>
                            <VerdictIcon className={`h-8 w-8 ${verdictStyle.iconClass}`} />
                        </div>

                        <div className="mt-4 h-2.5 overflow-hidden rounded-full bg-gray-200 dark:bg-gray-800">
                            <div
                                className={`h-full rounded-full transition-all duration-300 ${verdictStyle.progress}`}
                                style={{ width: `${riskScore}%` }}
                            />
                        </div>
                    </div>
                </div>

                <div className="w-full">
                    <div className="w-full space-y-2">
                        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                            Summary
                        </p>
                        <p className="w-full text-sm leading-6 text-gray-700 dark:text-gray-300">
                            {safeResult.reason}
                        </p>
                    </div>
                </div>

                {originTrace && (
                    <div className="space-y-4 rounded-2xl border border-gray-200 bg-white/80 p-4 dark:border-gray-700 dark:bg-gray-900/70">
                        <div className="space-y-2">
                            <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                Email Origin & Network Trace
                            </p>
                            <div className="flex flex-wrap gap-2">
                                {showTrustedProviderBadge && (
                                    <span className="inline-flex items-center rounded-full border border-cyan-200 bg-cyan-100 px-3 py-1 text-xs font-semibold text-cyan-800 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200">
                                        ✓ Trusted Provider Infrastructure: {trustedProviderLabel}
                                    </span>
                                )}
                                {showProxyWarning && (
                                    <span className="inline-flex items-center rounded-full border border-red-200 bg-red-100 px-3 py-1 text-xs font-semibold text-red-700 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200">
                                        ⚠️ VPN/Proxy Detected
                                    </span>
                                )}
                                {showHostingWarning && (
                                    <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-100 px-3 py-1 text-xs font-semibold text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200">
                                        ☁️ Cloud Host Origin
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                            <div className="rounded-xl border border-gray-200 bg-gray-50/90 p-4 dark:border-gray-700 dark:bg-gray-950/40">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gray-500 dark:text-gray-400">
                                    True Originating IP
                                </p>
                                <p className="mt-2 break-all font-mono text-sm font-semibold text-gray-900 dark:text-gray-100">
                                    {originTrace.originating_ip || 'Unknown'}
                                </p>
                            </div>

                            <div className="rounded-xl border border-gray-200 bg-gray-50/90 p-4 dark:border-gray-700 dark:bg-gray-950/40">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gray-500 dark:text-gray-400">
                                    Location
                                </p>
                                <p className="mt-2 text-sm font-semibold text-gray-900 dark:text-gray-100">
                                    {formatLocation(originTrace.location)}
                                </p>
                                {originTrace.origin_note && (
                                    <p className="mt-2 text-xs leading-5 text-gray-500 dark:text-gray-400">
                                        {originTrace.origin_note}
                                    </p>
                                )}
                            </div>

                            <div className="rounded-xl border border-gray-200 bg-gray-50/90 p-4 dark:border-gray-700 dark:bg-gray-950/40">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gray-500 dark:text-gray-400">
                                    ISP / ASN
                                </p>
                                <p className="mt-2 text-sm font-semibold text-gray-900 dark:text-gray-100">
                                    {formatIsp(originTrace.isp)}
                                </p>
                                {originTrace.isp?.organization && (
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        {originTrace.isp.organization}
                                    </p>
                                )}
                            </div>
                        </div>

                        <div className="space-y-3">
                            <div className="flex items-center justify-between gap-3">
                                <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                                    Network Hop Timeline
                                </p>
                                <span className="rounded-full bg-gray-100 px-3 py-1 text-xs font-semibold text-gray-700 dark:bg-gray-800 dark:text-gray-300">
                                    {originTrace.hop_count || hopsDetail.length} hops
                                </span>
                            </div>

                            {hopsDetail.length > 0 ? (
                                <div className="space-y-4">
                                    {hopsDetail.map((hop, index) => (
                                        <div key={`${hop.ip || 'unknown'}-${index}`} className="relative pl-12">
                                            {index < hopsDetail.length - 1 && (
                                                <div className="absolute left-4 top-10 h-[calc(100%-0.75rem)] w-px bg-gray-200 dark:bg-gray-700" />
                                            )}

                                            <div className="absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-full border border-gray-200 bg-white text-xs font-bold text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200">
                                                {hop.sequence || index + 1}
                                            </div>

                                            <div className="rounded-2xl border border-gray-200 bg-white/90 p-4 shadow-sm dark:border-gray-700 dark:bg-gray-900/80">
                                                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                                                    <div>
                                                        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gray-500 dark:text-gray-400">
                                                            {hop.source_header || 'Mail Hop'}
                                                        </p>
                                                        <p className="mt-2 break-all font-mono text-sm font-semibold text-gray-900 dark:text-gray-100">
                                                            {hop.ip || 'Unknown'}
                                                        </p>
                                                    </div>
                                                </div>
                                                {hop.raw_header && (
                                                    <p className="mt-3 break-words text-xs leading-5 text-gray-500 dark:text-gray-400">
                                                        {hop.raw_header}
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="rounded-2xl border border-dashed border-gray-300 bg-white/70 p-4 text-sm text-gray-600 dark:border-gray-700 dark:bg-gray-900/60 dark:text-gray-400">
                                    No relay hops were recorded for this trace.
                                </div>
                            )}
                        </div>
                    </div>
                )}

                <div className="w-full border-t border-gray-200 pt-4 dark:border-gray-700">
                    <button
                        type="button"
                        onClick={() => setIsExpanded((currentValue) => !currentValue)}
                        className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-3 text-left text-sm font-semibold text-gray-800 transition hover:bg-gray-100/80 dark:text-gray-100 dark:hover:bg-gray-800/70"
                        aria-expanded={isExpanded}
                    >
                        <span>View AI Investigation Steps</span>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </button>

                    {isExpanded && (
                        <div className="mt-4 space-y-4">
                            {analysisChain.length > 0 ? (
                                analysisChain.map((step, index) => (
                                    <div key={`${index}-${step}`} className="relative pl-12">
                                        {index < analysisChain.length - 1 && (
                                            <div className="absolute left-4 top-10 h-[calc(100%-0.75rem)] w-px bg-gray-200 dark:bg-gray-700" />
                                        )}

                                        <div className={`absolute left-0 top-0 flex h-8 w-8 items-center justify-center rounded-full border text-xs font-bold ${verdictStyle.badge}`}>
                                            {index + 1}
                                        </div>

                                        <div className="rounded-2xl border border-gray-200 bg-white/90 p-4 shadow-sm dark:border-gray-700 dark:bg-gray-900/80">
                                            <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-gray-500 dark:text-gray-400">
                                                Investigation Step {index + 1}
                                            </p>
                                            <p className="mt-2 text-sm leading-6 text-gray-700 dark:text-gray-300">
                                                {step}
                                            </p>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="rounded-2xl border border-dashed border-gray-300 bg-white/70 p-4 text-sm text-gray-600 dark:border-gray-700 dark:bg-gray-900/60 dark:text-gray-400">
                                    No AI investigation steps were recorded for this result.
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>
        </section>
    );
}
