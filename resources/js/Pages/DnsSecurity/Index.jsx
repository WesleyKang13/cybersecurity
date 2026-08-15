import InputError from '@/Components/InputError';
import InputLabel from '@/Components/InputLabel';
import Modal from '@/Components/Modal';
import PrimaryButton from '@/Components/PrimaryButton';
import SecondaryButton from '@/Components/SecondaryButton';
import TextInput from '@/Components/TextInput';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import IpIntelligenceModal from '@/Pages/Partials/IpIntelligenceModal';
import Tier3IntegrationGuideModal from '@/Pages/Partials/Tier3IntegrationGuideModal';
import { Head, router, useForm, usePage } from '@inertiajs/react';
import {
    AlertCircle,
    CheckCircle2,
    ChevronDown,
    ChevronUp,
    Copy,
    Globe,
    LoaderCircle,
    Plus,
    RefreshCw,
    RotateCcw,
    Search,
    ShieldAlert,
    ShieldCheck,
    Trash2,
} from 'lucide-react';
import { Fragment, useEffect, useState } from 'react';

const STATUS_STYLES = {
    Secure: 'border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-200',
    Warnings: 'border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200',
    Vulnerable: 'border-red-200 bg-red-100 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200',
    Critical: 'border-red-300 bg-red-600 text-white dark:border-red-500/30 dark:bg-red-600 dark:text-white',
};

const SEVERITY_STYLES = {
    critical: 'border-red-300 bg-red-600 text-white dark:border-red-500/30 dark:bg-red-600 dark:text-white',
    high: 'border-red-200 bg-red-100 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200',
    warning: 'border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200',
    info: 'border-cyan-200 bg-cyan-100 text-cyan-800 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200',
};

const STATUS_BADGE_STYLES = {
    secure: 'border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-200',
    mismatch: 'border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200',
    vulnerable: 'border-red-200 bg-red-100 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200',
    missing: 'border-red-200 bg-red-100 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200',
};

const ROWS_PER_PAGE_OPTIONS = [10, 25, 50];
const THREAT_ROWS_PER_PAGE_OPTIONS = [20, 50, 100, 'all'];

const WEB_HEADER_GUIDANCE = {
    'Content-Security-Policy': 'Limits which scripts, frames, and assets the browser is allowed to load.',
    'Strict-Transport-Security': 'Forces HTTPS and helps prevent protocol downgrade attacks.',
    'X-Frame-Options': 'Reduces clickjacking risk by restricting iframe embedding.',
    'X-Content-Type-Options': 'Stops browsers from MIME-sniffing untrusted content.',
};

const ACTION_BADGE_STYLES = {
    block: 'border-red-200 bg-red-100 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200',
    challenge: 'border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200',
    log: 'border-gray-300 bg-gray-100 text-gray-700 dark:border-gray-600 dark:bg-gray-700/50 dark:text-gray-200',
};

const TAB_STYLES = {
    active: 'border-gray-900 bg-gray-900 text-white dark:border-gray-100 dark:bg-gray-100 dark:text-gray-900',
    inactive: 'border-gray-200 bg-white text-gray-600 hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700',
};

const INFRASTRUCTURE_TYPE_OPTIONS = [
    {
        value: 'universal',
        label: 'Universal Scanner (Tier 1)',
        description: 'Passive monitoring for DNS health, SSL expiration, and HTTP security headers. No access required.',
    },
    {
        value: 'cloudflare',
        label: 'Cloudflare Edge WAF (Tier 2)',
        description: 'Perimeter defense and threat telemetry sync via Cloudflare API. Requires Zone ID.',
    },
    {
        value: 'app_middleware',
        label: 'Application Middleware (Tier 3)',
        description: 'In-app threat detection and local IP blocking via secure bearer token.',
    },
];

const getInfrastructureTypeLabel = (value) => {
    const option = INFRASTRUCTURE_TYPE_OPTIONS.find((item) => item.value === value);

    return option ? option.label : 'Universal Scanner (Tier 1)';
};

const normalizeStatusLabel = (value, fallback = 'Secure') => {
    const normalized = String(value || fallback).trim();

    return normalized !== '' ? normalized : fallback;
};

const getScoreBadgeStyles = (score) => {
    if (score >= 80) {
        return 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-200';
    }

    if (score >= 50) {
        return 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200';
    }

    return 'border-red-200 bg-red-50 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200';
};

const getSslStatusLabel = (scan) => {
    if (!scan) {
        return 'Pending';
    }

    return scan.ssl_valid ? 'Valid' : 'At Risk';
};

const getThreatActionStyle = (action) => {
    const normalizedAction = String(action || 'log').toLowerCase();

    return ACTION_BADGE_STYLES[normalizedAction] || ACTION_BADGE_STYLES.log;
};

const getThreatActionLabel = (action) => {
    const normalizedAction = String(action || 'log').trim();

    return normalizedAction !== '' ? normalizedAction : 'log';
};

const getThreatRowKey = (threat) => `${threat.domain_id}:${threat.attacker_ip}`;
const getAccessRuleRowKey = (rule) => `${rule.domain_id}:${rule.id}`;
const relativeTimeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

const getAddDomainProgressMessage = (elapsedMs) => {
    if (elapsedMs >= 4000) {
        return 'Auditing HTTP headers, latency, and SSL certificate...';
    }

    if (elapsedMs >= 2000) {
        return 'Querying DNS A, AAAA, MX, and TXT records...';
    }

    return 'Saving domain configuration...';
};

const getRelativeSyncLabel = (timestamp, nowMs) => {
    if (!timestamp) {
        return 'Waiting for first sync...';
    }

    const syncedAt = new Date(timestamp);

    if (Number.isNaN(syncedAt.getTime())) {
        return 'Waiting for first sync...';
    }

    const diffMs = syncedAt.getTime() - nowMs;
    const minuteMs = 60 * 1000;
    const hourMs = 60 * minuteMs;
    const dayMs = 24 * hourMs;

    if (Math.abs(diffMs) < hourMs) {
        return `Last checked ${relativeTimeFormatter.format(Math.round(diffMs / minuteMs), 'minute')}`;
    }

    if (Math.abs(diffMs) < dayMs) {
        return `Last checked ${relativeTimeFormatter.format(Math.round(diffMs / hourMs), 'hour')}`;
    }

    return `Last checked ${relativeTimeFormatter.format(Math.round(diffMs / dayMs), 'day')}`;
};

export default function DnsSecurityIndex({
    auth,
    domains = [],
    recentLogs = [],
    recentThreatLogs = [],
    activeAccessRules = [],
    threatAnalytics = {},
    last_synced_at = null,
    alertSettings = {},
}) {
    const { flash } = usePage().props;
    const [activeTab, setActiveTab] = useState('universal');
    const [showAddDomainModal, setShowAddDomainModal] = useState(false);
    const [showAlertSettingsModal, setShowAlertSettingsModal] = useState(false);
    const [showThreatSettingsModal, setShowThreatSettingsModal] = useState(false);
    const [selectedThreatDomain, setSelectedThreatDomain] = useState(null);
    const [showTier3GuideModal, setShowTier3GuideModal] = useState(false);
    const [tier3GuideDomain, setTier3GuideDomain] = useState(null);
    const [scanningDomainId, setScanningDomainId] = useState(null);
    const [deletingDomainId, setDeletingDomainId] = useState(null);
    const [copiedTokenDomainId, setCopiedTokenDomainId] = useState(null);
    const [severityFilter, setSeverityFilter] = useState('all');
    const [domainFilter, setDomainFilter] = useState('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [rowsPerPage, setRowsPerPage] = useState(10);
    const [threatRowsPerPage, setThreatRowsPerPage] = useState(20);
    const [currentPage, setCurrentPage] = useState(1);
    const [expandedLogIds, setExpandedLogIds] = useState({});
    const [expandedDomains, setExpandedDomains] = useState({});
    const [addDomainElapsedMs, setAddDomainElapsedMs] = useState(0);
    const [blockingThreatRows, setBlockingThreatRows] = useState({});
    const [blockedThreatRows, setBlockedThreatRows] = useState({});
    const [blockThreatErrors, setBlockThreatErrors] = useState({});
    const [unblockingRuleRows, setUnblockingRuleRows] = useState({});
    const [threatActionFeedback, setThreatActionFeedback] = useState(null);
    const [confirmBlockModal, setConfirmBlockModal] = useState({
        show: false,
        threat: null,
    });
    const [relativeTimeNow, setRelativeTimeNow] = useState(() => Date.now());
    const [ipLookupModal, setIpLookupModal] = useState({
        show: false,
        loading: false,
        ip: '',
        data: null,
        error: null,
    });

    const addDomainForm = useForm({
        domain: '',
        infrastructure_type: 'universal',
        cloudflare_zone_id: '',
    });

    const alertSettingsForm = useForm({
        email_enabled: Boolean(alertSettings.email_enabled),
        slack_enabled: Boolean(alertSettings.slack_enabled),
        discord_enabled: Boolean(alertSettings.discord_enabled),
        telegram_enabled: Boolean(alertSettings.telegram_enabled),
        slack_webhook_url: alertSettings.slack_webhook_url || '',
        discord_webhook_url: alertSettings.discord_webhook_url || '',
        telegram_bot_token: alertSettings.telegram_bot_token || '',
        telegram_chat_id: alertSettings.telegram_chat_id || '',
    });

    const threatSettingsForm = useForm({
        is_owned: false,
        cloudflare_zone_id: '',
        auto_ban_threshold: 10,
    });

    const domainOptions = domains
        .map((domain) => domain.domain)
        .sort((left, right) => left.localeCompare(right));

    const ownedDomains = domains.filter((domain) => domain.is_owned);
    const configuredOwnedDomains = ownedDomains.filter((domain) => {
        if (domain.infrastructure_type === 'app_middleware') {
            return String(domain.app_secret_token || '').trim() !== '';
        }

        return String(domain.cloudflare_zone_id || '').trim() !== '';
    });
    const selectedThreatDomainIsAppMiddleware = selectedThreatDomain?.infrastructure_type === 'app_middleware';
    const selectedThreatDomainIsUniversal = selectedThreatDomain?.infrastructure_type === 'universal';

    const filteredLogs = recentLogs.filter((log) => {
        const searchLower = searchTerm.trim().toLowerCase();

        if (severityFilter !== 'all' && String(log.severity || '').toLowerCase() !== severityFilter) {
            return false;
        }

        if (domainFilter !== 'all' && log.domain !== domainFilter) {
            return false;
        }

        if (searchLower === '') {
            return true;
        }

        return [
            log.domain,
            log.record_type,
            log.description,
            log.status,
            log.current_value,
            log.expected_value,
        ]
            .filter(Boolean)
            .some((value) => String(value).toLowerCase().includes(searchLower));
    });

    const hasActiveFilters =
        severityFilter !== 'all' || domainFilter !== 'all' || searchTerm.trim() !== '';
    const totalPages = Math.max(1, Math.ceil(filteredLogs.length / rowsPerPage));
    const safeCurrentPage = Math.min(currentPage, totalPages);
    const paginatedLogs = filteredLogs.slice(
        (safeCurrentPage - 1) * rowsPerPage,
        safeCurrentPage * rowsPerPage
    );
    const visibleThreatLogs =
        threatRowsPerPage === 'all'
            ? recentThreatLogs
            : recentThreatLogs.slice(0, Number(threatRowsPerPage));
    const hourlyAttackVolume = Array.isArray(threatAnalytics.hourly_attack_volume)
        ? threatAnalytics.hourly_attack_volume
        : [];
    const topTargetedPaths = Array.isArray(threatAnalytics.top_targeted_paths)
        ? threatAnalytics.top_targeted_paths
        : [];
    const topOriginCountries = Array.isArray(threatAnalytics.top_origin_countries)
        ? threatAnalytics.top_origin_countries
        : [];
    const totalThreatEvents = Number(threatAnalytics.total_events ?? recentThreatLogs.length ?? 0);
    const peakHourlyAttackCount = Math.max(
        1,
        ...hourlyAttackVolume.map((point) => Number(point.count || 0))
    );
    const lastSyncedLabel = getRelativeSyncLabel(last_synced_at, relativeTimeNow);

    const summary = domains.reduce(
        (accumulator, domain) => {
            accumulator.total += 1;
            accumulator.unresolved += Number(domain.unresolved_logs_count || 0);

            const status = normalizeStatusLabel(domain.overall_health_status);
            accumulator[status] = (accumulator[status] || 0) + 1;

            return accumulator;
        },
        { total: 0, unresolved: 0, Secure: 0, Warnings: 0, Vulnerable: 0, Critical: 0 }
    );

    const threatSummary = recentThreatLogs.reduce(
        (accumulator, threat) => {
            const action = String(threat.action_taken || '').toLowerCase();

            accumulator.total += 1;
            accumulator.block += action === 'block' ? 1 : 0;
            accumulator.challenge += action === 'challenge' ? 1 : 0;
            accumulator.log += action === 'log' ? 1 : 0;

            return accumulator;
        },
        { total: 0, block: 0, challenge: 0, log: 0 }
    );

    useEffect(() => {
        const intervalId = window.setInterval(() => {
            window.location.reload();
        }, 5 * 60 * 1000);

        return () => window.clearInterval(intervalId);
    }, []);

    useEffect(() => {
        const intervalId = window.setInterval(() => {
            setRelativeTimeNow(Date.now());
        }, 60 * 1000);

        return () => window.clearInterval(intervalId);
    }, []);

    useEffect(() => {
        if (!addDomainForm.processing) {
            setAddDomainElapsedMs(0);

            return undefined;
        }

        const timerId = window.setInterval(() => {
            setAddDomainElapsedMs((elapsedMs) => elapsedMs + 250);
        }, 250);

        return () => window.clearInterval(timerId);
    }, [addDomainForm.processing]);

    const closeAddDomainModal = () => {
        setShowAddDomainModal(false);
        setAddDomainElapsedMs(0);
        addDomainForm.reset();
        addDomainForm.setData('infrastructure_type', 'universal');
        addDomainForm.setData('cloudflare_zone_id', '');
        addDomainForm.clearErrors();
    };

    const openAlertSettingsModal = () => {
        alertSettingsForm.setData({
            email_enabled: Boolean(alertSettings.email_enabled),
            slack_enabled: Boolean(alertSettings.slack_enabled),
            discord_enabled: Boolean(alertSettings.discord_enabled),
            telegram_enabled: Boolean(alertSettings.telegram_enabled),
            slack_webhook_url: alertSettings.slack_webhook_url || '',
            discord_webhook_url: alertSettings.discord_webhook_url || '',
            telegram_bot_token: alertSettings.telegram_bot_token || '',
            telegram_chat_id: alertSettings.telegram_chat_id || '',
        });
        alertSettingsForm.clearErrors();
        setShowAlertSettingsModal(true);
    };

    const closeAlertSettingsModal = () => {
        setShowAlertSettingsModal(false);
        alertSettingsForm.clearErrors();
    };

    const openThreatSettingsModal = (domain) => {
        setSelectedThreatDomain(domain);
        threatSettingsForm.setData({
            is_owned: Boolean(domain.is_owned),
            cloudflare_zone_id: domain.cloudflare_zone_id || '',
            auto_ban_threshold: domain.auto_ban_threshold ?? 10,
        });
        threatSettingsForm.clearErrors();
        setShowThreatSettingsModal(true);
        setActiveTab('threats');
    };

    const closeThreatSettingsModal = () => {
        setShowThreatSettingsModal(false);
        setSelectedThreatDomain(null);
        threatSettingsForm.reset();
        threatSettingsForm.clearErrors();
    };

    const openTier3GuideModal = (domain) => {
        if (!domain) {
            return;
        }

        setTier3GuideDomain(domain);
        setShowTier3GuideModal(true);
    };

    const closeTier3GuideModal = () => {
        setShowTier3GuideModal(false);
        setTier3GuideDomain(null);
    };

    const openTier3GuideFromSettings = () => {
        const domain = selectedThreatDomain;

        if (!domain) {
            return;
        }

        closeThreatSettingsModal();
        openTier3GuideModal(domain);
    };

    const copyAppSecretToken = async (domain) => {
        if (!domain?.app_secret_token || !navigator?.clipboard?.writeText) {
            return;
        }

        try {
            await navigator.clipboard.writeText(domain.app_secret_token);
            setCopiedTokenDomainId(domain.id);
            window.setTimeout(() => {
                setCopiedTokenDomainId((current) => (current === domain.id ? null : current));
            }, 2000);
        } catch (error) {
            setCopiedTokenDomainId(null);
        }
    };

    const toggleExpandedLog = (logId) => {
        setExpandedLogIds((previousState) => ({
            ...previousState,
            [logId]: !previousState[logId],
        }));
    };

    const toggleExpandedDomain = (domainId) => {
        setExpandedDomains((previousState) => ({
            ...previousState,
            [domainId]: !previousState[domainId],
        }));
    };

    const closeIpLookupModal = () => {
        setIpLookupModal({
            show: false,
            loading: false,
            ip: '',
            data: null,
            error: null,
        });
    };

    const openConfirmBlockModal = (threat) => {
        setConfirmBlockModal({
            show: true,
            threat,
        });
    };

    const closeConfirmBlockModal = () => {
        setConfirmBlockModal({
            show: false,
            threat: null,
        });
    };

    const resetFilters = () => {
        setSeverityFilter('all');
        setDomainFilter('all');
        setSearchTerm('');
        setCurrentPage(1);
    };

    const submitDomain = (event) => {
        event.preventDefault();
        setAddDomainElapsedMs(0);

        addDomainForm.post(route('dns-security.store'), {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => closeAddDomainModal(),
            onError: () => {
                setAddDomainElapsedMs(0);
                setShowAddDomainModal(true);
            },
        });
    };

    const submitThreatSettings = (event) => {
        event.preventDefault();

        if (!selectedThreatDomain) {
            return;
        }

        threatSettingsForm.patch(route('dns-security.update', selectedThreatDomain.id), {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => closeThreatSettingsModal(),
        });
    };

    const submitAlertSettings = (event) => {
        event.preventDefault();

        alertSettingsForm.post(route('dns-security.alert-settings'), {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => closeAlertSettingsModal(),
            onError: () => setShowAlertSettingsModal(true),
        });
    };

    const scanDomain = (domainId) => {
        setScanningDomainId(domainId);

        router.post(route('dns-security.scan', domainId), {}, {
            preserveScroll: true,
            preserveState: true,
            onFinish: () => setScanningDomainId(null),
        });
    };

    const deleteDomain = (domain) => {
        if (!confirm(`Delete '${domain.domain}' from DNS monitoring?`)) {
            return;
        }

        setDeletingDomainId(domain.id);

        router.delete(route('dns-security.destroy', domain.id), {
            preserveScroll: true,
            preserveState: true,
            onFinish: () => setDeletingDomainId(null),
        });
    };

    const openIpLookupModal = async (ipAddress) => {
        setIpLookupModal({
            show: true,
            loading: true,
            ip: ipAddress,
            data: null,
            error: null,
        });

        try {
            const response = await fetch(`/dns-security/ip-lookup/${encodeURIComponent(ipAddress)}`, {
                headers: {
                    Accept: 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                credentials: 'same-origin',
            });

            const payload = await response.json();

            if (!response.ok || !payload.success) {
                throw new Error(payload.message || 'Unable to load IP intelligence.');
            }

            setIpLookupModal({
                show: true,
                loading: false,
                ip: ipAddress,
                data: payload.data,
                error: null,
            });
        } catch (error) {
            setIpLookupModal({
                show: true,
                loading: false,
                ip: ipAddress,
                data: null,
                error: error instanceof Error ? error.message : 'Unable to load IP intelligence.',
            });
        }
    };

    const blockThreatIp = (threat) => {
        const threatRowKey = getThreatRowKey(threat);

        setThreatActionFeedback(null);
        setBlockThreatErrors((previousState) => ({
            ...previousState,
            [threatRowKey]: null,
        }));
        setBlockingThreatRows((previousState) => ({
            ...previousState,
            [threatRowKey]: true,
        }));

        router.post(
            route('dns-security.block-ip'),
            {
                domain_id: threat.domain_id,
                ip_address: threat.attacker_ip,
            },
            {
                preserveScroll: true,
                preserveState: true,
                onSuccess: () => {
                    setBlockedThreatRows((previousState) => ({
                        ...previousState,
                        [threatRowKey]: true,
                    }));
                    setThreatActionFeedback({
                        type: 'success',
                        message: `Blocked ${threat.attacker_ip} on Cloudflare for ${threat.domain}.`,
                    });
                    closeConfirmBlockModal();
                },
                onError: (errors) => {
                    const message =
                        errors.block_ip ||
                        errors.domain_id ||
                        errors.ip_address ||
                        'Unable to block the IP on Cloudflare.';

                    setBlockThreatErrors((previousState) => ({
                        ...previousState,
                        [threatRowKey]: message,
                    }));
                    setThreatActionFeedback({
                        type: 'error',
                        message,
                    });
                },
                onFinish: () => {
                    setBlockingThreatRows((previousState) => ({
                        ...previousState,
                        [threatRowKey]: false,
                    }));
                },
            }
        );
    };

    const unblockAccessRule = (rule) => {
        const accessRuleRowKey = getAccessRuleRowKey(rule);

        setThreatActionFeedback(null);
        setUnblockingRuleRows((previousState) => ({
            ...previousState,
            [accessRuleRowKey]: true,
        }));

        router.post(
            route('dns-security.unblock-ip'),
            {
                domain_id: rule.domain_id,
                rule_id: rule.id,
            },
            {
                preserveScroll: true,
                preserveState: true,
                onFinish: () => {
                    setUnblockingRuleRows((previousState) => ({
                        ...previousState,
                        [accessRuleRowKey]: false,
                    }));
                },
            }
        );
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="text-xl font-semibold leading-tight text-gray-800">DNS Security Manager</h2>}
        >
            <Head title="DNS Security Manager" />

            <div className="py-10">
                <div className="mx-auto w-full max-w-[1920px] space-y-6 px-4 sm:px-6 lg:px-8">
                    {flash?.success && (
                        <div className="flex items-center gap-3 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 shadow-sm dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-100">
                            <CheckCircle2 className="h-5 w-5 shrink-0" />
                            <span>{flash.success}</span>
                        </div>
                    )}

                    {flash?.error && (
                        <div className="flex items-center gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 shadow-sm dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-100">
                            <AlertCircle className="h-5 w-5 shrink-0" />
                            <span>{flash.error}</span>
                        </div>
                    )}

                    <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
                        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                            <div className="max-w-3xl space-y-3">
                                <div className="inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-cyan-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-800 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200">
                                    <ShieldCheck className="h-4 w-4" />
                                    DNS Monitoring
                                </div>
                                <div>
                                    <h1 className="text-3xl font-black tracking-tight text-gray-900 dark:text-gray-100">
                                        DNS Security Manager
                                    </h1>
                                    <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-600 dark:text-gray-400">
                                        Monitor public-facing domains, audit web security posture, and review live attack telemetry for infrastructure you own.
                                    </p>
                                </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-3">
                                <button
                                    type="button"
                                    onClick={openAlertSettingsModal}
                                    className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-4 py-2.5 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                >
                                    <AlertCircle className="mr-2 h-4 w-4" />
                                    Notification Settings
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setShowAddDomainModal(true)}
                                    className="inline-flex items-center rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500"
                                >
                                    <Plus className="mr-2 h-4 w-4" />
                                    Add Domain
                                </button>
                            </div>
                        </div>

                        <div className="mt-6 flex flex-wrap gap-2">
                            <button
                                type="button"
                                onClick={() => setActiveTab('universal')}
                                className={`inline-flex items-center rounded-full border px-4 py-2 text-sm font-semibold transition ${activeTab === 'universal' ? TAB_STYLES.active : TAB_STYLES.inactive}`}
                            >
                                Universal Scanner
                            </button>
                            <button
                                type="button"
                                onClick={() => setActiveTab('threats')}
                                className={`inline-flex items-center rounded-full border px-4 py-2 text-sm font-semibold transition ${activeTab === 'threats' ? TAB_STYLES.active : TAB_STYLES.inactive}`}
                            >
                                My Infrastructure / Active Threats
                            </button>
                        </div>

                        {activeTab === 'universal' ? (
                            <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                                <div className="rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/50">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">Monitored Domains</p>
                                    <p className="mt-3 text-3xl font-black text-gray-900 dark:text-gray-100">{summary.total}</p>
                                </div>
                                <div className="rounded-2xl border border-emerald-200 bg-emerald-50/80 p-4 dark:border-emerald-500/30 dark:bg-emerald-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-emerald-700 dark:text-emerald-300">Secure</p>
                                    <p className="mt-3 text-3xl font-black text-emerald-900 dark:text-emerald-100">{summary.Secure}</p>
                                </div>
                                <div className="rounded-2xl border border-amber-200 bg-amber-50/80 p-4 dark:border-amber-500/30 dark:bg-amber-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-amber-700 dark:text-amber-300">Warnings</p>
                                    <p className="mt-3 text-3xl font-black text-amber-900 dark:text-amber-100">{summary.Warnings}</p>
                                </div>
                                <div className="rounded-2xl border border-red-200 bg-red-50/80 p-4 dark:border-red-500/30 dark:bg-red-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-red-700 dark:text-red-300">Vulnerable</p>
                                    <p className="mt-3 text-3xl font-black text-red-900 dark:text-red-100">{summary.Vulnerable}</p>
                                </div>
                                <div className="rounded-2xl border border-red-300 bg-red-600/95 p-4 text-white shadow-sm dark:border-red-500/30">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-red-100">Critical</p>
                                    <p className="mt-3 text-3xl font-black text-white">{summary.Critical}</p>
                                </div>
                            </div>
                        ) : (
                            <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                                <div className="rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/50">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">Owned Domains</p>
                                    <p className="mt-3 text-3xl font-black text-gray-900 dark:text-gray-100">{ownedDomains.length}</p>
                                </div>
                                <div className="rounded-2xl border border-cyan-200 bg-cyan-50/80 p-4 dark:border-cyan-500/30 dark:bg-cyan-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-700 dark:text-cyan-300">Zones Configured</p>
                                    <p className="mt-3 text-3xl font-black text-cyan-900 dark:text-cyan-100">{configuredOwnedDomains.length}</p>
                                </div>
                                <div className="rounded-2xl border border-red-200 bg-red-50/80 p-4 dark:border-red-500/30 dark:bg-red-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-red-700 dark:text-red-300">Blocked</p>
                                    <p className="mt-3 text-3xl font-black text-red-900 dark:text-red-100">{threatSummary.block}</p>
                                </div>
                                <div className="rounded-2xl border border-amber-200 bg-amber-50/80 p-4 dark:border-amber-500/30 dark:bg-amber-500/10">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-amber-700 dark:text-amber-300">Challenged</p>
                                    <p className="mt-3 text-3xl font-black text-amber-900 dark:text-amber-100">{threatSummary.challenge}</p>
                                </div>
                                <div className="rounded-2xl border border-gray-300 bg-gray-900 p-4 text-white shadow-sm dark:border-gray-600">
                                    <p className="text-xs font-semibold uppercase tracking-[0.22em] text-gray-200">Threat Events</p>
                                    <p className="mt-3 text-3xl font-black text-white">{threatSummary.total}</p>
                                </div>
                            </div>
                        )}
                    </section>

                    {activeTab === 'universal' ? (
                        <Fragment>
                            <section className="space-y-4">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Monitored Domains</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Review DNS posture, web security health, and trigger manual scans.
                                        </p>
                                    </div>
                                    <div className="rounded-full bg-gray-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-gray-600 dark:bg-gray-800 dark:text-gray-300">
                                        {summary.unresolved} unresolved findings
                                    </div>
                                </div>

                                {domains.length > 0 ? (
                                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                                        {domains.map((domain) => {
                                            const statusLabel = normalizeStatusLabel(domain.overall_health_status);
                                            const statusStyle = STATUS_STYLES[statusLabel] || STATUS_STYLES.Secure;
                                            const isScanning = scanningDomainId === domain.id;
                                            const isDeleting = deletingDomainId === domain.id;
                                            const isExpanded = Boolean(expandedDomains[domain.id]);
                                            const webScan = domain.web_security_scan;
                                            const scoreValue = Number(webScan?.security_score ?? 0);
                                            const scoreBadgeStyle = getScoreBadgeStyles(scoreValue);
                                            const missingHeaders = Array.isArray(webScan?.missing_headers)
                                                ? webScan.missing_headers
                                                : [];
                                            const detectedIssues = Array.isArray(webScan?.detected_issues)
                                                ? webScan.detected_issues
                                                : [];

                                            return (
                                                <article
                                                    key={domain.id}
                                                    className="rounded-3xl border border-gray-200 bg-white p-4 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md dark:border-gray-700 dark:bg-gray-800"
                                                >
                                                    <button
                                                        type="button"
                                                        onClick={() => toggleExpandedDomain(domain.id)}
                                                        className="flex w-full items-start justify-between gap-3 text-left"
                                                    >
                                                        <div className="min-w-0 flex-1">
                                                            <div className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-gray-100 text-gray-700 dark:bg-gray-900 dark:text-gray-200">
                                                                <Globe className="h-5 w-5" />
                                                            </div>
                                                            <div className="mt-3">
                                                                <h4 className="break-all text-base font-bold text-gray-900 dark:text-gray-100">
                                                                    {domain.domain}
                                                                </h4>
                                                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                    Last checked {domain.last_checked_at_formatted}
                                                                </p>
                                                            </div>
                                                        </div>

                                                        <div className="shrink-0 space-y-2 text-right">
                                                            <span className={`inline-flex rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-wide ${statusStyle}`}>
                                                                {statusLabel}
                                                            </span>
                                                            <div className={`inline-flex rounded-full border px-3 py-1 text-xs font-bold ${scoreBadgeStyle}`}>
                                                                {webScan ? `${scoreValue}/100` : 'Pending'}
                                                            </div>
                                                        </div>
                                                    </button>

                                                    <div className="mt-4 flex flex-col gap-3 rounded-2xl border border-gray-200 bg-gray-50/80 p-3 dark:border-gray-700 dark:bg-gray-900/60">
                                                        <div className="flex items-center justify-between gap-3">
                                                            <span className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                Open Findings
                                                            </span>
                                                            <span className="text-lg font-black text-gray-900 dark:text-gray-100">
                                                                {domain.unresolved_logs_count}
                                                            </span>
                                                        </div>

                                                        <div className="flex flex-wrap items-center gap-2">
                                                            <button
                                                                type="button"
                                                                onClick={() => scanDomain(domain.id)}
                                                                disabled={isScanning || isDeleting}
                                                                className="inline-flex items-center rounded-xl bg-gray-900 px-3 py-2 text-sm font-semibold text-white transition hover:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
                                                            >
                                                                {isScanning ? (
                                                                    <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                                                                ) : (
                                                                    <RefreshCw className="mr-2 h-4 w-4" />
                                                                )}
                                                                Scan Now
                                                            </button>

                                                            <button
                                                                type="button"
                                                                onClick={() => deleteDomain(domain)}
                                                                disabled={isScanning || isDeleting}
                                                                className="inline-flex items-center rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200"
                                                            >
                                                                {isDeleting ? (
                                                                    <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                                                                ) : (
                                                                    <Trash2 className="mr-2 h-4 w-4" />
                                                                )}
                                                                Delete
                                                            </button>

                                                            <button
                                                                type="button"
                                                                onClick={() => toggleExpandedDomain(domain.id)}
                                                                className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-3 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
                                                            >
                                                                {isExpanded ? (
                                                                    <ChevronUp className="mr-2 h-4 w-4" />
                                                                ) : (
                                                                    <ChevronDown className="mr-2 h-4 w-4" />
                                                                )}
                                                                {isExpanded ? 'Collapse' : 'Expand'}
                                                            </button>
                                                        </div>
                                                    </div>

                                                    <div className={`grid overflow-hidden transition-all duration-300 ease-out ${isExpanded ? 'mt-4 grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`}>
                                                        <div className="min-h-0 overflow-hidden">
                                                            <div className="space-y-4 rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/60">
                                                                <div className="flex flex-wrap items-center justify-between gap-3">
                                                                    <div>
                                                                        <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                                                            Web Security &amp; Health
                                                                        </p>
                                                                        <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                            {webScan?.scanned_at_formatted
                                                                                ? `Updated ${webScan.scanned_at_formatted}`
                                                                                : 'Pending first web audit'}
                                                                        </p>
                                                                    </div>

                                                                    <div className="flex flex-wrap gap-2">
                                                                        <span className="inline-flex items-center rounded-full border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200">
                                                                            Critical {domain.critical_count}
                                                                        </span>
                                                                        <span className="inline-flex items-center rounded-full border border-orange-200 bg-orange-50 px-2.5 py-1 text-xs font-semibold text-orange-700 dark:border-orange-500/30 dark:bg-orange-500/15 dark:text-orange-200">
                                                                            High {domain.high_count}
                                                                        </span>
                                                                        <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200">
                                                                            Warning {domain.warning_count}
                                                                        </span>
                                                                    </div>
                                                                </div>

                                                                {webScan ? (
                                                                    <div className="space-y-3">
                                                                        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                                                                            <div className="rounded-2xl bg-white px-3 py-2 shadow-sm dark:bg-gray-800">
                                                                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">SSL</p>
                                                                                <p className="mt-1 text-sm font-bold text-gray-900 dark:text-gray-100">
                                                                                    {getSslStatusLabel(webScan)}
                                                                                </p>
                                                                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                                    {webScan.ssl_expires_at_formatted
                                                                                        ? `Expires ${webScan.ssl_expires_at_formatted}`
                                                                                        : 'Certificate details unavailable'}
                                                                                </p>
                                                                            </div>

                                                                            <div className="rounded-2xl bg-white px-3 py-2 shadow-sm dark:bg-gray-800">
                                                                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Latency</p>
                                                                                <p className="mt-1 text-sm font-bold text-gray-900 dark:text-gray-100">
                                                                                    {webScan.response_time_ms !== null ? `${webScan.response_time_ms} ms` : 'Timed out'}
                                                                                </p>
                                                                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                                    HTTP {webScan.http_status ?? 'No response'}
                                                                                </p>
                                                                            </div>

                                                                            <div className="rounded-2xl bg-white px-3 py-2 shadow-sm dark:bg-gray-800">
                                                                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Issuer</p>
                                                                                <p className="mt-1 text-sm font-bold text-gray-900 dark:text-gray-100">
                                                                                    {webScan.ssl_issuer || 'Unknown'}
                                                                                </p>
                                                                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                                    {missingHeaders.length} missing header{missingHeaders.length === 1 ? '' : 's'}
                                                                                </p>
                                                                            </div>
                                                                        </div>

                                                                        <div className="space-y-2">
                                                                            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                                Missing Security Headers
                                                                            </p>
                                                                            {missingHeaders.length > 0 ? (
                                                                                <div className="space-y-2">
                                                                                    {missingHeaders.map((headerName) => (
                                                                                        <div
                                                                                            key={`${domain.id}-${headerName}`}
                                                                                            className="rounded-2xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-100"
                                                                                        >
                                                                                            <p className="font-semibold">{headerName}</p>
                                                                                            <p className="mt-1 leading-5 text-amber-800/90 dark:text-amber-100/90">
                                                                                                {WEB_HEADER_GUIDANCE[headerName] || 'Critical security header is missing from the response.'}
                                                                                            </p>
                                                                                        </div>
                                                                                    ))}
                                                                                </div>
                                                                            ) : (
                                                                                <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-100">
                                                                                    All audited security headers are present.
                                                                                </div>
                                                                            )}
                                                                        </div>

                                                                        {detectedIssues.length > 0 && (
                                                                            <div className="space-y-2">
                                                                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                                    Findings
                                                                                </p>
                                                                                <ul className="space-y-2 text-xs text-gray-600 dark:text-gray-300">
                                                                                    {detectedIssues.slice(0, 4).map((issue, index) => (
                                                                                        <li
                                                                                            key={`${domain.id}-issue-${index}`}
                                                                                            className="rounded-2xl border border-gray-200 bg-white px-3 py-2 leading-5 shadow-sm dark:border-gray-700 dark:bg-gray-800"
                                                                                        >
                                                                                            {issue}
                                                                                        </li>
                                                                                    ))}
                                                                                </ul>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                ) : (
                                                                    <div className="rounded-2xl border border-dashed border-gray-300 px-3 py-3 text-sm text-gray-500 dark:border-gray-700 dark:text-gray-400">
                                                                        A web security audit will appear here after the first scan completes.
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </article>
                                            );
                                        })}
                                    </div>
                                ) : (
                                    <div className="rounded-3xl border border-dashed border-gray-300 bg-white p-8 text-center shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                        <ShieldAlert className="mx-auto h-10 w-10 text-gray-400" />
                                        <h4 className="mt-4 text-lg font-bold text-gray-900 dark:text-gray-100">No monitored domains yet</h4>
                                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                            Add your first domain to start tracking SPF, DKIM, DMARC, and DNS baseline drift.
                                        </p>
                                        <button
                                            type="button"
                                            onClick={() => setShowAddDomainModal(true)}
                                            className="mt-5 inline-flex items-center rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500"
                                        >
                                            <Plus className="mr-2 h-4 w-4" />
                                            Add Domain
                                        </button>
                                    </div>
                                )}
                            </section>

                            <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Security Findings &amp; Logs</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Filter recent DNS findings by severity and monitored domain.
                                        </p>
                                    </div>
                                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                        Showing {filteredLogs.length} finding{filteredLogs.length === 1 ? '' : 's'}
                                    </div>
                                </div>

                                <div className="mt-5 rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/40">
                                    <div className="grid gap-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,0.9fr)_minmax(0,1.2fr)_auto]">
                                        <label className="space-y-1">
                                            <span className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Severity</span>
                                            <select
                                                value={severityFilter}
                                                onChange={(event) => {
                                                    setSeverityFilter(event.target.value);
                                                    setCurrentPage(1);
                                                }}
                                                className="w-full rounded-xl border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
                                            >
                                                <option value="all">All severities</option>
                                                <option value="critical">Critical</option>
                                                <option value="high">High</option>
                                                <option value="warning">Warning</option>
                                                <option value="info">Info</option>
                                            </select>
                                        </label>

                                        <label className="space-y-1">
                                            <span className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Domain</span>
                                            <select
                                                value={domainFilter}
                                                onChange={(event) => {
                                                    setDomainFilter(event.target.value);
                                                    setCurrentPage(1);
                                                }}
                                                className="w-full rounded-xl border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
                                            >
                                                <option value="all">All domains</option>
                                                {domainOptions.map((domainOption) => (
                                                    <option key={domainOption} value={domainOption}>
                                                        {domainOption}
                                                    </option>
                                                ))}
                                            </select>
                                        </label>

                                        <label className="space-y-1">
                                            <span className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Search</span>
                                            <div className="relative">
                                                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                                                <input
                                                    type="text"
                                                    value={searchTerm}
                                                    onChange={(event) => {
                                                        setSearchTerm(event.target.value);
                                                        setCurrentPage(1);
                                                    }}
                                                    placeholder="Search findings..."
                                                    className="w-full rounded-xl border-gray-300 py-2 pl-9 pr-3 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
                                                />
                                            </div>
                                        </label>

                                        <div className="flex items-end">
                                            {hasActiveFilters ? (
                                                <button
                                                    type="button"
                                                    onClick={resetFilters}
                                                    className="inline-flex w-full items-center justify-center rounded-xl border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                                >
                                                    <RotateCcw className="mr-2 h-4 w-4" />
                                                    Reset Filters
                                                </button>
                                            ) : (
                                                <div className="hidden lg:block" />
                                            )}
                                        </div>
                                    </div>
                                </div>

                                <div className="mt-6 overflow-hidden rounded-2xl border border-gray-200 dark:border-gray-700">
                                    <div className="max-h-[720px] overflow-auto">
                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                            <thead className="sticky top-0 z-10 bg-gray-50/95 backdrop-blur dark:bg-gray-900/95">
                                                <tr>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Domain</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Record</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Severity</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Status</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Details</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Detected</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-800">
                                                {paginatedLogs.length > 0 ? (
                                                    paginatedLogs.map((log) => {
                                                        const severity = String(log.severity || 'info').toLowerCase();
                                                        const status = String(log.status || 'secure').toLowerCase();
                                                        const severityStyle = SEVERITY_STYLES[severity] || SEVERITY_STYLES.info;
                                                        const statusStyle = STATUS_BADGE_STYLES[status] || STATUS_BADGE_STYLES.secure;
                                                        const isExpanded = Boolean(expandedLogIds[log.id]);
                                                        const hasDetailPanel =
                                                            Boolean(log.expected_value) ||
                                                            Boolean(log.current_value) ||
                                                            String(log.description || '').length > 120;

                                                        return (
                                                            <Fragment key={log.id}>
                                                                <tr className="align-top transition hover:bg-gray-50/80 dark:hover:bg-gray-900/30">
                                                                    <td className="px-4 py-4 text-sm font-semibold text-gray-900 dark:text-gray-100">
                                                                        <div>{log.domain}</div>
                                                                        {log.is_resolved && (
                                                                            <div className="mt-1 text-xs font-medium text-emerald-600 dark:text-emerald-300">
                                                                                Resolved {log.resolved_at_formatted}
                                                                            </div>
                                                                        )}
                                                                    </td>
                                                                    <td className="px-4 py-4 text-sm font-mono text-gray-700 dark:text-gray-300">
                                                                        {log.record_type}
                                                                    </td>
                                                                    <td className="px-4 py-4">
                                                                        <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${severityStyle}`}>
                                                                            {severity}
                                                                        </span>
                                                                    </td>
                                                                    <td className="px-4 py-4">
                                                                        <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${statusStyle}`}>
                                                                            {status}
                                                                        </span>
                                                                    </td>
                                                                    <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                        <div className="flex items-start justify-between gap-4">
                                                                            <p className="max-w-[42rem] truncate leading-6">
                                                                                {log.description}
                                                                            </p>
                                                                            {hasDetailPanel && (
                                                                                <button
                                                                                    type="button"
                                                                                    onClick={() => toggleExpandedLog(log.id)}
                                                                                    className="inline-flex shrink-0 items-center rounded-full border border-gray-200 bg-white px-2.5 py-1 text-xs font-semibold text-gray-600 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:bg-gray-800"
                                                                                >
                                                                                    {isExpanded ? (
                                                                                        <ChevronUp className="mr-1 h-3.5 w-3.5" />
                                                                                    ) : (
                                                                                        <ChevronDown className="mr-1 h-3.5 w-3.5" />
                                                                                    )}
                                                                                    {isExpanded ? 'Hide' : 'Details'}
                                                                                </button>
                                                                            )}
                                                                        </div>
                                                                    </td>
                                                                    <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                                                                        {log.created_at_formatted}
                                                                    </td>
                                                                </tr>

                                                                {hasDetailPanel && isExpanded && (
                                                                    <tr className="bg-gray-50/80 dark:bg-gray-900/25">
                                                                        <td colSpan="6" className="px-4 pb-4 pt-1">
                                                                            <div className="rounded-2xl border border-gray-200 bg-white p-4 text-sm shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                                                                <p className="leading-6 text-gray-700 dark:text-gray-300">
                                                                                    {log.description}
                                                                                </p>

                                                                                {(log.expected_value || log.current_value) && (
                                                                                    <div className="mt-4 grid gap-3 xl:grid-cols-2">
                                                                                        {log.expected_value && (
                                                                                            <div className="rounded-2xl bg-gray-50 p-3 dark:bg-gray-900/60">
                                                                                                <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                                                    Expected
                                                                                                </span>
                                                                                                <p className="mt-2 break-all font-mono text-xs leading-6 text-gray-700 dark:text-gray-300">
                                                                                                    {log.expected_value}
                                                                                                </p>
                                                                                            </div>
                                                                                        )}

                                                                                        {log.current_value && (
                                                                                            <div className="rounded-2xl bg-gray-50 p-3 dark:bg-gray-900/60">
                                                                                                <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                                                    Current
                                                                                                </span>
                                                                                                <p className="mt-2 break-all font-mono text-xs leading-6 text-gray-700 dark:text-gray-300">
                                                                                                    {log.current_value}
                                                                                                </p>
                                                                                            </div>
                                                                                        )}
                                                                                    </div>
                                                                                )}
                                                                            </div>
                                                                        </td>
                                                                    </tr>
                                                                )}
                                                            </Fragment>
                                                        );
                                                    })
                                                ) : (
                                                    <tr>
                                                        <td colSpan="6" className="px-4 py-10 text-center text-sm text-gray-500 dark:text-gray-400">
                                                            No DNS findings match the selected filters.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <div className="mt-4 flex flex-col gap-3 border-t border-gray-200 pt-4 dark:border-gray-700 sm:flex-row sm:items-center sm:justify-between">
                                    <div className="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400">
                                        <span>Rows per page</span>
                                        <select
                                            value={rowsPerPage}
                                            onChange={(event) => {
                                                setRowsPerPage(Number(event.target.value));
                                                setCurrentPage(1);
                                            }}
                                            className="rounded-xl border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
                                        >
                                            {ROWS_PER_PAGE_OPTIONS.map((option) => (
                                                <option key={option} value={option}>
                                                    {option}
                                                </option>
                                            ))}
                                        </select>
                                        <span>
                                            Page {safeCurrentPage} of {totalPages}
                                        </span>
                                    </div>

                                    <div className="flex items-center gap-2">
                                        <button
                                            type="button"
                                            onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                                            disabled={safeCurrentPage === 1}
                                            className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                        >
                                            Previous
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
                                            disabled={safeCurrentPage === totalPages}
                                            className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                        >
                                            Next
                                        </button>
                                    </div>
                                </div>
                            </section>
                        </Fragment>
                    ) : (
                        <Fragment>
                            <section className="space-y-4">
                                <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Owned Infrastructure</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Configure owned domains for Cloudflare edge telemetry or application-level middleware reporting.
                                        </p>
                                    </div>
                                    <div className="rounded-full bg-gray-100 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-gray-600 dark:bg-gray-800 dark:text-gray-300">
                                        {configuredOwnedDomains.length} of {domains.length} domains configured
                                    </div>
                                </div>

                                {domains.length > 0 ? (
                                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                                        {domains.map((domain) => {
                                            const recentThreats = Array.isArray(domain.recent_threats)
                                                ? domain.recent_threats
                                                : [];
                                            const latestThreat = recentThreats[0] || null;

                                            return (
                                                <article
                                                    key={`threat-${domain.id}`}
                                                    className="rounded-3xl border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-700 dark:bg-gray-800"
                                                >
                                                    <div className="flex items-start justify-between gap-3">
                                                        <div className="min-w-0 flex-1">
                                                            <h4 className="break-all text-base font-bold text-gray-900 dark:text-gray-100">
                                                                {domain.domain}
                                                            </h4>
                                                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                {domain.is_owned
                                                                    ? `${getInfrastructureTypeLabel(domain.infrastructure_type)}${domain.infrastructure_type === 'app_middleware' ? ' integration' : ''}`
                                                                    : domain.infrastructure_type === 'universal'
                                                                        ? getInfrastructureTypeLabel(domain.infrastructure_type)
                                                                        : 'Monitored externally only'}
                                                            </p>
                                                        </div>

                                                        <span
                                                            className={`inline-flex rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-wide ${
                                                                domain.is_owned
                                                                    ? 'border-cyan-200 bg-cyan-100 text-cyan-800 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200'
                                                                    : 'border-gray-200 bg-gray-100 text-gray-700 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300'
                                                            }`}
                                                        >
                                                            {domain.is_owned ? 'Owned' : 'External'}
                                                        </span>
                                                    </div>

                                                    <div className="mt-4 rounded-2xl border border-gray-200 bg-gray-50 px-3 py-3 text-sm dark:border-gray-700 dark:bg-gray-900/60">
                                                        <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                            {domain.infrastructure_type === 'app_middleware'
                                                                ? 'Integration Type'
                                                                : domain.infrastructure_type === 'universal'
                                                                    ? 'Monitoring Mode'
                                                                    : 'Cloudflare Zone ID'}
                                                        </p>
                                                        {domain.infrastructure_type === 'app_middleware' ? (
                                                            <p className="mt-2 text-xs font-semibold text-gray-700 dark:text-gray-300">
                                                                Application middleware publishes threat telemetry directly with a bearer token.
                                                            </p>
                                                        ) : domain.infrastructure_type === 'universal' ? (
                                                            <p className="mt-2 text-xs font-semibold text-gray-700 dark:text-gray-300">
                                                                Passive DNS, SSL, and HTTP security header audits with no infrastructure access required.
                                                            </p>
                                                        ) : (
                                                            <p className="mt-2 break-all font-mono text-xs text-gray-700 dark:text-gray-300">
                                                                {domain.cloudflare_zone_id || 'Not configured'}
                                                            </p>
                                                        )}
                                                    </div>

                                                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                                                        <div className="rounded-2xl bg-gray-50 px-3 py-3 dark:bg-gray-900/60">
                                                            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                Latest Threat
                                                            </p>
                                                            <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                                                {latestThreat ? latestThreat.detected_at_formatted : 'No recent events'}
                                                            </p>
                                                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                {latestThreat ? `${latestThreat.action_taken} from ${latestThreat.country || 'Unknown'}` : 'Waiting for threat sync'}
                                                            </p>
                                                        </div>

                                                        <div className="rounded-2xl bg-gray-50 px-3 py-3 dark:bg-gray-900/60">
                                                            <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">
                                                                Recent Events
                                                            </p>
                                                            <p className="mt-2 text-2xl font-black text-gray-900 dark:text-gray-100">
                                                                {domain.recent_events_count ?? 0}
                                                            </p>
                                                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                Past 24 hours
                                                            </p>
                                                        </div>
                                                    </div>

                                                    <div className="mt-4 space-y-2">
                                                        {recentThreats.length > 0 ? (
                                                            recentThreats.slice(0, 3).map((threat) => (
                                                                <div
                                                                    key={`${domain.id}-${threat.id}`}
                                                                    className="rounded-2xl border border-gray-200 bg-white px-3 py-2 text-xs shadow-sm dark:border-gray-700 dark:bg-gray-800"
                                                                >
                                                                    <div className="flex items-start justify-between gap-2">
                                                                        <div className="min-w-0">
                                                                            <p className="truncate font-semibold text-gray-900 dark:text-gray-100">
                                                                                {threat.attacker_ip}
                                                                            </p>
                                                                            <p className="mt-1 truncate text-gray-500 dark:text-gray-400">
                                                                                {threat.path_targeted || 'No path provided'}
                                                                            </p>
                                                                        </div>
                                                                        <span className={`inline-flex rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${getThreatActionStyle(threat.action_taken)}`}>
                                                                            {getThreatActionLabel(threat.action_taken)}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <div className="rounded-2xl border border-dashed border-gray-300 px-3 py-3 text-xs text-gray-500 dark:border-gray-700 dark:text-gray-400">
                                                                No recent Cloudflare firewall events loaded for this domain.
                                                            </div>
                                                        )}
                                                    </div>

                                                    <div className="mt-4">
                                                        <button
                                                            type="button"
                                                            onClick={() => openThreatSettingsModal(domain)}
                                                            className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                                        >
                                                            {domain.infrastructure_type === 'app_middleware'
                                                                ? 'View Integration'
                                                                : domain.infrastructure_type === 'cloudflare'
                                                                    ? 'Configure Cloudflare'
                                                                    : 'View Monitoring Mode'}
                                                        </button>
                                                    </div>
                                                </article>
                                            );
                                        })}
                                    </div>
                                ) : (
                                    <div className="rounded-3xl border border-dashed border-gray-300 bg-white p-8 text-center shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                        <ShieldAlert className="mx-auto h-10 w-10 text-gray-400" />
                                        <h4 className="mt-4 text-lg font-bold text-gray-900 dark:text-gray-100">No domains available</h4>
                                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                            Add a domain first, then choose passive posture scanning or an owned-infrastructure integration mode.
                                        </p>
                                    </div>
                                )}
                            </section>

                            <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">24-Hour Threat Analytics</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Distribution of attack volume, top targeted routes, and leading source geographies across owned infrastructure.
                                        </p>
                                    </div>
                                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                        {totalThreatEvents} total event{totalThreatEvents === 1 ? '' : 's'}
                                    </div>
                                </div>

                                {totalThreatEvents > 0 ? (
                                    <div className="mt-6 grid gap-4 xl:grid-cols-[1.35fr_1fr_1fr]">
                                        <div className="rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/50">
                                            <div className="flex items-center justify-between gap-3">
                                                <div>
                                                    <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                                        Hourly Attack Volume
                                                    </p>
                                                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                                        Attack traffic trend over the last 24 hours.
                                                    </p>
                                                </div>
                                                <div className="rounded-full border border-gray-200 bg-white px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-gray-600 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300">
                                                    Peak {peakHourlyAttackCount}
                                                </div>
                                            </div>

                                            <div className="mt-5 flex h-52 items-end gap-2">
                                                {hourlyAttackVolume.map((point, index) => {
                                                    const count = Number(point.count || 0);
                                                    const heightPercent = Math.max(6, Math.round((count / peakHourlyAttackCount) * 100));

                                                    return (
                                                        <div key={`${point.time}-${index}`} className="flex min-w-0 flex-1 flex-col items-center justify-end gap-2">
                                                            <span className="text-[10px] font-semibold text-gray-500 dark:text-gray-400">
                                                                {count > 0 ? count : ''}
                                                            </span>
                                                            <div className="flex h-36 w-full items-end rounded-full bg-gray-200/80 px-1 py-1 dark:bg-gray-800">
                                                                <div
                                                                    className="w-full rounded-full bg-gradient-to-t from-red-600 via-orange-500 to-amber-300 transition-all"
                                                                    style={{ height: `${count === 0 ? 6 : heightPercent}%` }}
                                                                />
                                                            </div>
                                                            <span className="text-[10px] text-gray-500 dark:text-gray-400">
                                                                {index % 3 === 0 ? point.time : '·'}
                                                            </span>
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </div>

                                        <div className="rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/50">
                                            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                                Top Attack Targets
                                            </p>
                                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                                Most frequently probed paths in the last 24 hours.
                                            </p>

                                            <div className="mt-5 space-y-4">
                                                {topTargetedPaths.length > 0 ? (
                                                    topTargetedPaths.map((entry) => (
                                                        <div key={entry.path} className="space-y-2">
                                                            <div className="flex items-center justify-between gap-3">
                                                                <p className="truncate font-mono text-sm font-semibold text-gray-900 dark:text-gray-100">
                                                                    {entry.path}
                                                                </p>
                                                                <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">
                                                                    {entry.count} · {entry.percentage}%
                                                                </span>
                                                            </div>
                                                            <div className="h-2.5 rounded-full bg-gray-200 dark:bg-gray-800">
                                                                <div
                                                                    className="h-2.5 rounded-full bg-gradient-to-r from-indigo-600 to-cyan-400"
                                                                    style={{ width: `${Math.max(6, Number(entry.percentage || 0))}%` }}
                                                                />
                                                            </div>
                                                        </div>
                                                    ))
                                                ) : (
                                                    <div className="rounded-2xl border border-dashed border-gray-300 px-3 py-4 text-sm text-gray-500 dark:border-gray-700 dark:text-gray-400">
                                                        No targeted paths are available yet.
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        <div className="rounded-2xl border border-gray-200 bg-gray-50/80 p-4 dark:border-gray-700 dark:bg-gray-900/50">
                                            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">
                                                Geographic Breakdown
                                            </p>
                                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                                Top source countries observed in Cloudflare threat telemetry.
                                            </p>

                                            <div className="mt-5 space-y-4">
                                                {topOriginCountries.length > 0 ? (
                                                    topOriginCountries.map((entry) => (
                                                        <div key={entry.country} className="space-y-2">
                                                            <div className="flex items-center justify-between gap-3">
                                                                <div className="flex items-center gap-2">
                                                                    <span className="inline-flex rounded-full border border-cyan-200 bg-cyan-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-cyan-700 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-200">
                                                                        {entry.country}
                                                                    </span>
                                                                </div>
                                                                <span className="text-xs font-semibold text-gray-500 dark:text-gray-400">
                                                                    {entry.count} · {entry.percentage}%
                                                                </span>
                                                            </div>
                                                            <div className="h-2.5 rounded-full bg-gray-200 dark:bg-gray-800">
                                                                <div
                                                                    className="h-2.5 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                                                                    style={{ width: `${Math.max(6, Number(entry.percentage || 0))}%` }}
                                                                />
                                                            </div>
                                                        </div>
                                                    ))
                                                ) : (
                                                    <div className="rounded-2xl border border-dashed border-gray-300 px-3 py-4 text-sm text-gray-500 dark:border-gray-700 dark:text-gray-400">
                                                        No country-level attack data is available yet.
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="mt-6 rounded-3xl border border-dashed border-gray-300 bg-gray-50/70 px-6 py-12 text-center dark:border-gray-700 dark:bg-gray-900/40">
                                        <ShieldCheck className="mx-auto h-12 w-12 text-emerald-500 dark:text-emerald-300" />
                                        <h4 className="mt-4 text-lg font-bold text-gray-900 dark:text-gray-100">
                                            No threat activity detected in the past 24 hours
                                        </h4>
                                        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                            Cloudflare telemetry has not reported recent attacks for your owned infrastructure.
                                        </p>
                                    </div>
                                )}
                            </section>

                            <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Active Threat Events</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Recent Cloudflare firewall events across owned infrastructure from the past 24 hours.
                                        </p>
                                    </div>
                                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                        Showing {visibleThreatLogs.length} of {recentThreatLogs.length} event{recentThreatLogs.length === 1 ? '' : 's'}
                                    </div>
                                </div>

                                {threatActionFeedback && (
                                    <div
                                        className={`mt-4 flex items-center gap-3 rounded-2xl border px-4 py-3 text-sm shadow-sm ${
                                            threatActionFeedback.type === 'success'
                                                ? 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-100'
                                                : 'border-red-200 bg-red-50 text-red-800 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-100'
                                        }`}
                                    >
                                        {threatActionFeedback.type === 'success' ? (
                                            <CheckCircle2 className="h-5 w-5 shrink-0" />
                                        ) : (
                                            <AlertCircle className="h-5 w-5 shrink-0" />
                                        )}
                                        <span>{threatActionFeedback.message}</span>
                                    </div>
                                )}

                                <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-end">
                                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                        {lastSyncedLabel}
                                    </div>
                                    <label className="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400">
                                        <span>Show rows</span>
                                        <select
                                            value={threatRowsPerPage}
                                            onChange={(event) =>
                                                setThreatRowsPerPage(
                                                    event.target.value === 'all'
                                                        ? 'all'
                                                        : Number(event.target.value)
                                                )
                                            }
                                            className="rounded-xl border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
                                        >
                                            {THREAT_ROWS_PER_PAGE_OPTIONS.map((option) => (
                                                <option key={option} value={option}>
                                                    {option === 'all' ? 'All' : option}
                                                </option>
                                            ))}
                                        </select>
                                    </label>
                                </div>

                                <div className="mt-6 overflow-hidden rounded-2xl border border-gray-200 dark:border-gray-700">
                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                            <thead className="bg-gray-50 dark:bg-gray-900/60">
                                                <tr>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Date / Time</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Attacker IP</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Country</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Targeted Path</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Action</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Source</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Mitigation</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-800">
                                                {visibleThreatLogs.length > 0 ? (
                                                    visibleThreatLogs.map((threat) => {
                                                        const threatRowKey = getThreatRowKey(threat);
                                                        const isBlockingThreat = Boolean(blockingThreatRows[threatRowKey]);
                                                        const isBlockedThreat = Boolean(blockedThreatRows[threatRowKey]);
                                                        const blockThreatError = blockThreatErrors[threatRowKey];

                                                        return (
                                                            <tr key={threat.id} className="hover:bg-gray-50/80 dark:hover:bg-gray-900/30">
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    <div className="font-medium text-gray-900 dark:text-gray-100">
                                                                        {threat.detected_at_formatted}
                                                                    </div>
                                                                    <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                        {threat.detected_at_relative}
                                                                    </div>
                                                                </td>
                                                                <td className="px-4 py-4 text-sm font-mono">
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => openIpLookupModal(threat.attacker_ip)}
                                                                        className="font-semibold text-indigo-600 transition hover:text-indigo-500 dark:text-indigo-300 dark:hover:text-indigo-200"
                                                                    >
                                                                        {threat.attacker_ip}
                                                                    </button>
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    {threat.country || 'Unknown'}
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    <div className="font-medium text-gray-900 dark:text-gray-100">
                                                                        {threat.path_targeted || '/'}
                                                                    </div>
                                                                    <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                                        {threat.domain}
                                                                    </div>
                                                                </td>
                                                                <td className="px-4 py-4">
                                                                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${getThreatActionStyle(threat.action_taken)}`}>
                                                                        {getThreatActionLabel(threat.action_taken)}
                                                                    </span>
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    {threat.threat_source || 'Unknown'}
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    <div className="flex flex-col items-start gap-2">
                                                                        <button
                                                                            type="button"
                                                                            onClick={() => openConfirmBlockModal(threat)}
                                                                            disabled={isBlockingThreat || isBlockedThreat}
                                                                            className="inline-flex items-center rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200"
                                                                        >
                                                                            {isBlockingThreat ? (
                                                                                <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                                                                            ) : null}
                                                                            {isBlockedThreat ? 'Blocked' : 'Block IP'}
                                                                        </button>

                                                                        {isBlockedThreat && (
                                                                            <span className="inline-flex rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-200">
                                                                                Blocked on Cloudflare
                                                                            </span>
                                                                        )}

                                                                        {blockThreatError ? (
                                                                            <span className="text-xs text-red-600 dark:text-red-300">
                                                                                {blockThreatError}
                                                                            </span>
                                                                        ) : null}
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })
                                                ) : (
                                                    <tr>
                                                        <td colSpan="7" className="px-4 py-10 text-center text-sm text-gray-500 dark:text-gray-400">
                                                            No Cloudflare threat events are loaded yet. Configure a Zone ID for an owned domain and run the threat sync command.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </section>

                            <section className="rounded-3xl border border-gray-200 bg-white p-6 shadow-sm dark:border-gray-700 dark:bg-gray-800">
                                <div className="flex flex-col gap-2 lg:flex-row lg:items-end lg:justify-between">
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 dark:text-gray-100">Active Edge Access Rules</h3>
                                        <p className="text-sm text-gray-500 dark:text-gray-400">
                                            Cloudflare IP block rules currently active across configured owned domains.
                                        </p>
                                    </div>
                                    <div className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                        {activeAccessRules.length} active rule{activeAccessRules.length === 1 ? '' : 's'}
                                    </div>
                                </div>

                                <div className="mt-6 overflow-hidden rounded-2xl border border-gray-200 dark:border-gray-700">
                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                            <thead className="bg-gray-50 dark:bg-gray-900/60">
                                                <tr>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Domain</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Blocked IP</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Rule Notes</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Created</th>
                                                    <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Action</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-200 bg-white dark:divide-gray-700 dark:bg-gray-800">
                                                {activeAccessRules.length > 0 ? (
                                                    activeAccessRules.map((rule) => {
                                                        const accessRuleRowKey = getAccessRuleRowKey(rule);
                                                        const isUnblockingRule = Boolean(unblockingRuleRows[accessRuleRowKey]);

                                                        return (
                                                            <tr key={`${rule.domain_id}-${rule.id}`} className="hover:bg-gray-50/80 dark:hover:bg-gray-900/30">
                                                                <td className="px-4 py-4 text-sm font-semibold text-gray-900 dark:text-gray-100">
                                                                    {rule.domain}
                                                                </td>
                                                                <td className="px-4 py-4 text-sm font-mono text-gray-700 dark:text-gray-300">
                                                                    {rule.ip_address}
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-700 dark:text-gray-300">
                                                                    {rule.notes || 'No notes provided'}
                                                                </td>
                                                                <td className="px-4 py-4 text-sm text-gray-500 dark:text-gray-400">
                                                                    {rule.created_on_formatted || 'Unknown'}
                                                                </td>
                                                                <td className="px-4 py-4">
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => unblockAccessRule(rule)}
                                                                        disabled={isUnblockingRule}
                                                                        className="inline-flex items-center rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-red-500/30 dark:bg-red-500/15 dark:text-red-200"
                                                                    >
                                                                        {isUnblockingRule ? (
                                                                            <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                                                                        ) : null}
                                                                        Unblock IP
                                                                    </button>
                                                                </td>
                                                            </tr>
                                                        );
                                                    })
                                                ) : (
                                                    <tr>
                                                        <td colSpan="5" className="px-4 py-10 text-center text-sm text-gray-500 dark:text-gray-400">
                                                            No active Cloudflare edge access rules are currently loaded.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </section>
                        </Fragment>
                    )}
                </div>
            </div>

            <Modal show={showAddDomainModal} onClose={closeAddDomainModal} maxWidth="md">
                <form onSubmit={submitDomain} className="bg-white p-6 dark:bg-gray-800">
                    <div className="space-y-2">
                        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Add Monitored Domain</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Add a domain to track SPF, DKIM, DMARC, and DNS baseline changes.
                        </p>
                    </div>

                    <div className="mt-6 space-y-4">
                        <div>
                            <InputLabel htmlFor="domain" value="Domain Name" />
                            <TextInput
                                id="domain"
                                type="text"
                                value={addDomainForm.data.domain}
                                onChange={(event) => addDomainForm.setData('domain', event.target.value)}
                                className="mt-1 block w-full font-mono text-sm"
                                placeholder="example.com"
                                required
                                autoFocus
                            />
                            <InputError message={addDomainForm.errors.domain} className="mt-2" />
                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                Full URLs are accepted and will be normalized automatically.
                            </p>
                        </div>

                        <div>
                            <InputLabel htmlFor="infrastructure_type" value="Infrastructure Type" />
                            <div className="mt-3 grid gap-3">
                                {INFRASTRUCTURE_TYPE_OPTIONS.map((option) => {
                                    const isSelected = addDomainForm.data.infrastructure_type === option.value;

                                    return (
                                        <label
                                            key={option.value}
                                            className={`flex cursor-pointer items-start gap-3 rounded-2xl border px-4 py-4 text-sm transition ${
                                                isSelected
                                                    ? 'border-indigo-500 bg-indigo-50 shadow-sm dark:border-indigo-400 dark:bg-indigo-500/10'
                                                    : 'border-gray-200 bg-white hover:border-indigo-300 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:hover:border-indigo-500/50 dark:hover:bg-gray-800'
                                            }`}
                                        >
                                            <input
                                                type="radio"
                                                name="infrastructure_type"
                                                value={option.value}
                                                checked={isSelected}
                                                onChange={(event) => {
                                                    const nextType = event.target.value;
                                                    addDomainForm.setData('infrastructure_type', nextType);

                                                    if (nextType !== 'cloudflare') {
                                                        addDomainForm.setData('cloudflare_zone_id', '');
                                                    }
                                                }}
                                                className="mt-1 border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                                            />
                                            <span className="min-w-0">
                                                <span className="block font-semibold text-gray-900 dark:text-gray-100">
                                                    {option.label}
                                                </span>
                                                <span className="mt-1 block text-xs leading-5 text-gray-500 dark:text-gray-400">
                                                    {option.description}
                                                </span>
                                            </span>
                                        </label>
                                    );
                                })}
                            </div>
                            <InputError message={addDomainForm.errors.infrastructure_type} className="mt-2" />
                        </div>

                        {addDomainForm.data.infrastructure_type === 'cloudflare' && (
                            <div>
                                <InputLabel htmlFor="add_cloudflare_zone_id" value="Cloudflare Zone ID" />
                                <TextInput
                                    id="add_cloudflare_zone_id"
                                    type="text"
                                    value={addDomainForm.data.cloudflare_zone_id}
                                    onChange={(event) => addDomainForm.setData('cloudflare_zone_id', event.target.value)}
                                    className="mt-1 block w-full font-mono text-sm"
                                    placeholder="023e105f4ecef8ad9ca31a8372d0c353"
                                />
                                <InputError message={addDomainForm.errors.cloudflare_zone_id} className="mt-2" />
                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                    Optional during creation. Add it now if this is owned Cloudflare-backed infrastructure and you want threat telemetry immediately.
                                </p>
                            </div>
                        )}

                        {addDomainForm.data.infrastructure_type === 'app_middleware' && (
                            <div className="rounded-2xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm text-cyan-900 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-100">
                                A secure 64-character application token will be generated automatically after this domain is created.
                            </div>
                        )}

                        {addDomainForm.data.infrastructure_type === 'universal' && (
                            <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-100">
                                Universal posture scans run passively and do not require Cloudflare credentials or middleware tokens.
                            </div>
                        )}
                    </div>

                    <div className="mt-6 flex justify-end gap-3">
                        <SecondaryButton onClick={closeAddDomainModal} disabled={addDomainForm.processing}>
                            Cancel
                        </SecondaryButton>
                        <div className="flex min-w-[18rem] flex-col items-end gap-2">
                            <PrimaryButton disabled={addDomainForm.processing}>
                                {addDomainForm.processing && <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />}
                                {addDomainForm.processing ? 'Running Checks...' : 'Add Domain'}
                            </PrimaryButton>

                            {addDomainForm.processing && (
                                <div className="flex w-full items-start gap-3 rounded-2xl border border-indigo-200 bg-indigo-50 px-4 py-3 text-left text-sm text-indigo-900 shadow-sm transition dark:border-indigo-500/30 dark:bg-indigo-500/15 dark:text-indigo-100">
                                    <LoaderCircle className="mt-0.5 h-5 w-5 shrink-0 animate-spin" />
                                    <div>
                                        <p className="font-semibold">Preparing full domain audit</p>
                                        <p className="mt-1 leading-5">
                                            {getAddDomainProgressMessage(addDomainElapsedMs)}
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </form>
            </Modal>

            <Modal show={showAlertSettingsModal} onClose={closeAlertSettingsModal} maxWidth="lg">
                <form onSubmit={submitAlertSettings} className="bg-white p-6 dark:bg-gray-800">
                    <div className="space-y-2">
                        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Configure Alerts</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Enable delivery channels for DNS drift, SSL expiry warnings, and attack spike alerts.
                        </p>
                    </div>

                    <div className="mt-6 grid gap-4">
                        <label className="flex items-start gap-3 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 text-sm dark:border-gray-700 dark:bg-gray-900/60">
                            <input
                                type="checkbox"
                                checked={alertSettingsForm.data.email_enabled}
                                onChange={(event) => alertSettingsForm.setData('email_enabled', event.target.checked)}
                                className="mt-1 rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                            />
                            <span>
                                <span className="block font-semibold text-gray-900 dark:text-gray-100">Email Alerts</span>
                                <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">
                                    Send alerts to your account email address.
                                </span>
                            </span>
                        </label>

                        <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-4 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 dark:border-gray-700 dark:bg-gray-900/60">
                                <label className="flex items-start gap-3 text-sm">
                                    <input
                                        type="checkbox"
                                        checked={alertSettingsForm.data.slack_enabled}
                                        onChange={(event) => alertSettingsForm.setData('slack_enabled', event.target.checked)}
                                        className="mt-1 rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                                    />
                                    <span>
                                        <span className="block font-semibold text-gray-900 dark:text-gray-100">Slack Webhook</span>
                                        <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">
                                            Post rich alerts into a Slack channel via incoming webhook.
                                        </span>
                                    </span>
                                </label>
                                <div>
                                    <InputLabel htmlFor="slack_webhook_url" value="Slack Webhook URL" />
                                    <TextInput
                                        id="slack_webhook_url"
                                        type="url"
                                        value={alertSettingsForm.data.slack_webhook_url}
                                        onChange={(event) => alertSettingsForm.setData('slack_webhook_url', event.target.value)}
                                        className="mt-1 block w-full text-sm"
                                        placeholder="https://hooks.slack.com/services/..."
                                        disabled={!alertSettingsForm.data.slack_enabled}
                                    />
                                    <InputError message={alertSettingsForm.errors.slack_webhook_url} className="mt-2" />
                                </div>
                            </div>

                            <div className="space-y-4 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 dark:border-gray-700 dark:bg-gray-900/60">
                                <label className="flex items-start gap-3 text-sm">
                                    <input
                                        type="checkbox"
                                        checked={alertSettingsForm.data.discord_enabled}
                                        onChange={(event) => alertSettingsForm.setData('discord_enabled', event.target.checked)}
                                        className="mt-1 rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                                    />
                                    <span>
                                        <span className="block font-semibold text-gray-900 dark:text-gray-100">Discord Webhook</span>
                                        <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">
                                            Push alerts into a Discord channel webhook.
                                        </span>
                                    </span>
                                </label>
                                <div>
                                    <InputLabel htmlFor="discord_webhook_url" value="Discord Webhook URL" />
                                    <TextInput
                                        id="discord_webhook_url"
                                        type="url"
                                        value={alertSettingsForm.data.discord_webhook_url}
                                        onChange={(event) => alertSettingsForm.setData('discord_webhook_url', event.target.value)}
                                        className="mt-1 block w-full text-sm"
                                        placeholder="https://discord.com/api/webhooks/..."
                                        disabled={!alertSettingsForm.data.discord_enabled}
                                    />
                                    <InputError message={alertSettingsForm.errors.discord_webhook_url} className="mt-2" />
                                </div>
                            </div>
                        </div>

                        <div className="space-y-4 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 dark:border-gray-700 dark:bg-gray-900/60">
                            <label className="flex items-start gap-3 text-sm">
                                <input
                                    type="checkbox"
                                    checked={alertSettingsForm.data.telegram_enabled}
                                    onChange={(event) => alertSettingsForm.setData('telegram_enabled', event.target.checked)}
                                    className="mt-1 rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                                />
                                <span>
                                    <span className="block font-semibold text-gray-900 dark:text-gray-100">Telegram Alerts</span>
                                    <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">
                                        Send alert messages through your Telegram bot and chat destination.
                                    </span>
                                </span>
                            </label>

                            <div className="grid gap-4 md:grid-cols-2">
                                <div>
                                    <InputLabel htmlFor="telegram_bot_token" value="Telegram Bot Token" />
                                    <TextInput
                                        id="telegram_bot_token"
                                        type="text"
                                        value={alertSettingsForm.data.telegram_bot_token}
                                        onChange={(event) => alertSettingsForm.setData('telegram_bot_token', event.target.value)}
                                        className="mt-1 block w-full font-mono text-sm"
                                        placeholder="123456789:AA..."
                                        disabled={!alertSettingsForm.data.telegram_enabled}
                                    />
                                    <InputError message={alertSettingsForm.errors.telegram_bot_token} className="mt-2" />
                                </div>

                                <div>
                                    <InputLabel htmlFor="telegram_chat_id" value="Telegram Chat ID" />
                                    <TextInput
                                        id="telegram_chat_id"
                                        type="text"
                                        value={alertSettingsForm.data.telegram_chat_id}
                                        onChange={(event) => alertSettingsForm.setData('telegram_chat_id', event.target.value)}
                                        className="mt-1 block w-full font-mono text-sm"
                                        placeholder="-1001234567890"
                                        disabled={!alertSettingsForm.data.telegram_enabled}
                                    />
                                    <InputError message={alertSettingsForm.errors.telegram_chat_id} className="mt-2" />
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="mt-6 flex justify-end gap-3">
                        <SecondaryButton onClick={closeAlertSettingsModal} disabled={alertSettingsForm.processing}>
                            Cancel
                        </SecondaryButton>
                        <PrimaryButton disabled={alertSettingsForm.processing}>
                            {alertSettingsForm.processing && <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />}
                            Save Alert Settings
                        </PrimaryButton>
                    </div>
                </form>
            </Modal>

            <Modal show={confirmBlockModal.show} onClose={closeConfirmBlockModal} maxWidth="md">
                <div className="bg-white p-6 dark:bg-gray-800">
                    <div className="space-y-2">
                        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Confirm Cloudflare IP Ban</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Review the mitigation target before deploying a Cloudflare edge block rule.
                        </p>
                    </div>

                    {confirmBlockModal.threat && (
                        <div className="mt-6 space-y-4">
                            <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 dark:border-gray-700 dark:bg-gray-900/60">
                                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Targeted IP Address</p>
                                <p className="mt-2 font-mono text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {confirmBlockModal.threat.attacker_ip}
                                </p>
                                <p className="mt-3 text-[11px] font-semibold uppercase tracking-[0.2em] text-gray-500 dark:text-gray-400">Domain</p>
                                <p className="mt-2 text-sm font-bold text-gray-900 dark:text-gray-100">
                                    {confirmBlockModal.threat.domain}
                                </p>
                            </div>

                            <div className="flex items-start gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-4 text-sm text-amber-900 dark:border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-100">
                                <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" />
                                <p className="leading-6">
                                    Caution: Blocking this IP will prevent all web traffic from this address from accessing your site at the Cloudflare edge network.
                                </p>
                            </div>
                        </div>
                    )}

                    <div className="mt-6 flex justify-end gap-3">
                        <SecondaryButton onClick={closeConfirmBlockModal} disabled={confirmBlockModal.threat ? Boolean(blockingThreatRows[getThreatRowKey(confirmBlockModal.threat)]) : false}>
                            Cancel
                        </SecondaryButton>
                        <button
                            type="button"
                            onClick={() => confirmBlockModal.threat && blockThreatIp(confirmBlockModal.threat)}
                            disabled={confirmBlockModal.threat ? Boolean(blockingThreatRows[getThreatRowKey(confirmBlockModal.threat)]) : true}
                            className="inline-flex items-center rounded-xl border border-red-300 bg-red-600 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                            {confirmBlockModal.threat && Boolean(blockingThreatRows[getThreatRowKey(confirmBlockModal.threat)]) ? (
                                <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />
                            ) : null}
                            Confirm &amp; Block IP
                        </button>
                    </div>
                </div>
            </Modal>

            <IpIntelligenceModal state={ipLookupModal} onClose={closeIpLookupModal} />
            <Tier3IntegrationGuideModal
                isOpen={showTier3GuideModal}
                onClose={closeTier3GuideModal}
                domainName={tier3GuideDomain?.domain}
                appSecretToken={tier3GuideDomain?.app_secret_token}
            />

            <Modal show={showThreatSettingsModal} onClose={closeThreatSettingsModal} maxWidth="md">
                <form onSubmit={submitThreatSettings} className="bg-white p-6 dark:bg-gray-800">
                    <div className="space-y-2">
                        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Infrastructure Settings</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Review the current infrastructure type and configure the integration details used for active threat telemetry.
                        </p>
                    </div>

                    {selectedThreatDomain && (
                        <div className="mt-4 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 text-sm dark:border-gray-700 dark:bg-gray-900/60">
                            <p className="font-semibold text-gray-900 dark:text-gray-100">{selectedThreatDomain.domain}</p>
                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                {getInfrastructureTypeLabel(selectedThreatDomain.infrastructure_type)}
                            </p>
                        </div>
                    )}

                    <div className="mt-6 space-y-4">
                        <div>
                            <InputLabel htmlFor="auto_ban_threshold" value="Auto-Ban Threat Threshold" />
                            <TextInput
                                id="auto_ban_threshold"
                                type="number"
                                min="1"
                                step="1"
                                value={threatSettingsForm.data.auto_ban_threshold}
                                onChange={(event) => threatSettingsForm.setData('auto_ban_threshold', event.target.value)}
                                className="mt-1 block w-full text-sm"
                                placeholder="10"
                            />
                            <InputError message={threatSettingsForm.errors.auto_ban_threshold} className="mt-2" />
                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                Auto-ban enabled integrations will block an IP after it reaches this many threat reports within the detection window.
                            </p>
                        </div>

                        {selectedThreatDomainIsAppMiddleware ? (
                            <Fragment>
                                <div className="rounded-2xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm text-cyan-900 dark:border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-100">
                                    Application middleware domains are treated as owned infrastructure automatically so they can report telemetry back to this manager.
                                </div>

                                <div className="rounded-2xl border border-gray-200 bg-gray-50 px-4 py-4 dark:border-gray-700 dark:bg-gray-900/60">
                                    <div className="flex items-center justify-between gap-3">
                                        <div>
                                            <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">Integration Credentials</p>
                                            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                Add this token to your external application's environment file to securely transmit threat logs back to this manager.
                                            </p>
                                        </div>
                                        <button
                                            type="button"
                                            onClick={() => copyAppSecretToken(selectedThreatDomain)}
                                            className="inline-flex items-center rounded-xl border border-gray-300 bg-white px-3 py-2 text-xs font-semibold text-gray-700 transition hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-200 dark:hover:bg-gray-800"
                                        >
                                            {copiedTokenDomainId === selectedThreatDomain?.id ? (
                                                <CheckCircle2 className="mr-2 h-4 w-4" />
                                            ) : (
                                                <Copy className="mr-2 h-4 w-4" />
                                            )}
                                            {copiedTokenDomainId === selectedThreatDomain?.id ? 'Copied' : 'Copy to Clipboard'}
                                        </button>
                                    </div>

                                    <div className="mt-4">
                                        <InputLabel htmlFor="app_secret_token" value="Application Secret Token" />
                                        <TextInput
                                            id="app_secret_token"
                                            type="text"
                                            value={selectedThreatDomain?.app_secret_token || ''}
                                            readOnly
                                            className="mt-1 block w-full font-mono text-sm"
                                        />
                                    </div>

                                    <div className="mt-4 flex justify-end">
                                        <PrimaryButton type="button" onClick={openTier3GuideFromSettings}>
                                            Open Tier 3 Integration Guide
                                        </PrimaryButton>
                                    </div>
                                </div>
                            </Fragment>
                        ) : selectedThreatDomainIsUniversal ? (
                            <Fragment>
                                <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-100">
                                    Universal Scanner domains are always passive. They monitor DNS posture, SSL expiration, and web security headers without Cloudflare access or application credentials.
                                </div>
                            </Fragment>
                        ) : (
                            <Fragment>
                                <label className="flex items-start gap-3 rounded-2xl border border-gray-200 bg-gray-50 px-4 py-3 text-sm dark:border-gray-700 dark:bg-gray-900/60">
                                    <input
                                        type="checkbox"
                                        checked={threatSettingsForm.data.is_owned}
                                        onChange={(event) => threatSettingsForm.setData('is_owned', event.target.checked)}
                                        className="mt-1 rounded border-gray-300 text-indigo-600 shadow-sm focus:ring-indigo-500 dark:border-gray-600 dark:bg-gray-900"
                                    />
                                    <span>
                                        <span className="block font-semibold text-gray-900 dark:text-gray-100">This is infrastructure we own</span>
                                        <span className="mt-1 block text-xs text-gray-500 dark:text-gray-400">
                                            Only owned infrastructure should be connected to Cloudflare threat telemetry.
                                        </span>
                                    </span>
                                </label>

                                <div>
                                    <InputLabel htmlFor="cloudflare_zone_id" value="Cloudflare Zone ID" />
                                    <TextInput
                                        id="cloudflare_zone_id"
                                        type="text"
                                        value={threatSettingsForm.data.cloudflare_zone_id}
                                        onChange={(event) => threatSettingsForm.setData('cloudflare_zone_id', event.target.value)}
                                        className="mt-1 block w-full font-mono text-sm"
                                        placeholder="023e105f4ecef8ad9ca31a8372d0c353"
                                        disabled={!threatSettingsForm.data.is_owned}
                                    />
                                    <InputError message={threatSettingsForm.errors.cloudflare_zone_id} className="mt-2" />
                                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                        Stored on the monitored domain so the threat sync command can query Cloudflare GraphQL for this zone.
                                    </p>
                                </div>
                            </Fragment>
                        )}
                    </div>

                    <div className="mt-6 flex justify-end gap-3">
                        <SecondaryButton onClick={closeThreatSettingsModal} disabled={threatSettingsForm.processing}>
                            Cancel
                        </SecondaryButton>
                        <PrimaryButton disabled={threatSettingsForm.processing}>
                            {threatSettingsForm.processing && <LoaderCircle className="mr-2 h-4 w-4 animate-spin" />}
                            Save Settings
                        </PrimaryButton>
                    </div>
                </form>
            </Modal>
        </AuthenticatedLayout>
    );
}
