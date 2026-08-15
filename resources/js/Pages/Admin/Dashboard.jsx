import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, router, useForm, usePage } from '@inertiajs/react';
import { useState } from 'react';
import IpIntelligenceModal from '@/Pages/Partials/IpIntelligenceModal';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';
import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import InputLabel from '@/Components/InputLabel';
import InputError from '@/Components/InputError';
import {
    ShieldAlert, Mail, MessageSquare, Users, LayoutDashboard, UserPlus,
    FileText, Calendar, TrendingUp, CheckCircle, Smartphone, ShieldCheck,
    Server, RefreshCw, AlertTriangle, Globe2, Download, KeyRound, Eye, EyeOff, History
} from 'lucide-react';
import DomainManagerTab from './DomainManager';

const parseFailedJobPayload = (payload) => {
    if (!payload || typeof payload !== 'string') {
        return null;
    }

    try {
        return JSON.parse(payload);
    } catch (error) {
        return null;
    }
};

const getFailedJobDisplayName = (payload) => {
    const parsedPayload = parseFailedJobPayload(payload);

    return parsedPayload?.displayName || parsedPayload?.job || parsedPayload?.data?.commandName || 'Unknown Job';
};

const truncateText = (text, maxLength = 180) => {
    const normalized = String(text || '').trim();

    if (normalized.length <= maxLength) {
        return normalized;
    }

    return `${normalized.slice(0, maxLength)}...`;
};

const maskToken = (token) => {
    const normalized = String(token || '').trim();

    if (!normalized) {
        return 'No token provisioned';
    }

    if (normalized.length <= 14) {
        return normalized;
    }

    return `${normalized.slice(0, 8)}••••••••••••${normalized.slice(-6)}`;
};

const formatAuditAction = (action) =>
    String(action || '')
        .split('_')
        .filter(Boolean)
        .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
        .join(' ') || 'Unknown action';

const getAuditActorLabel = (user) => {
    if (!user) {
        return 'System';
    }

    return user.name || user.email || 'Unknown user';
};

export default function AdminDashboard({
    auth,
    threats,
    users,
    reportData,
    filters,
    domains,
    pending_jobs_count = 0,
    failed_jobs_count = 0,
    recent_failed_jobs = [],
    top_targeted_paths = [],
    top_attacker_ips = [],
    tier_3_domains = [],
    audit_logs = [],
}) {
    // 👇 Active Tab State
    const { props } = usePage(); // Get page props to check for errors
    const { flash } = props;

    const [activeTab, setActiveTab] = useState(() => {
        if (reportData) return 'reports';
        // If there are errors (e.g. "Email required") likely from the Add User form
        if (props.errors && Object.keys(props.errors).length > 0) return 'users';
        return 'threats';
    });

    // Modals
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [showThreatModal, setShowThreatModal] = useState(false);
    const [showUserModal, setShowUserModal] = useState(false);

    const [showEditUserModal, setShowEditUserModal] = useState(false);
    const [editingUser, setEditingUser] = useState(null);
    const [retryingFailedJobs, setRetryingFailedJobs] = useState(false);
    const [revealedTokens, setRevealedTokens] = useState({});
    const [rotatingDomainId, setRotatingDomainId] = useState(null);
    const [togglingDomainId, setTogglingDomainId] = useState(null);
    const [ipLookupModal, setIpLookupModal] = useState({
        show: false,
        loading: false,
        ip: '',
        data: null,
        error: null,
    });

    // Form: Add User
    const { data, setData, post, processing, reset, errors } = useForm({
        name: '', email: '',
    });

    const editForm = useForm({
        id: '', name: '', email: '', role: '', password: ''
    });

    const openThreatModal = (threat) => {
        setSelectedThreat(threat);
        setShowThreatModal(true);
    };

    const submitUser = (e) => {
        e.preventDefault();
        post(route('admin.users.store'), {
            onSuccess: () => { setShowUserModal(false); reset(); },
        });
    };

    const openEditUserModal = (user) => {
        setEditingUser(user);
        editForm.setData({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role || 'user',
            password: '', // Always start password empty on edit
        });
        setShowEditUserModal(true);
    };

    const submitEditUser = (e) => {
        e.preventDefault();
        // Uses the PUT method pointing to a new update route
        editForm.put(route('admin.users.update', editingUser.id), {
            onSuccess: () => {
                setShowEditUserModal(false);
                editForm.reset('password');
            },
        });
    };

    const reportForm = useForm({
        start_date: filters?.start_date || '',
        end_date: filters?.end_date || ''
    });

    // 👇 Handle Report Generation
    const submitReport = (e) => {
        e.preventDefault();
        reportForm.get(route('admin.dashboard'), {
            onSuccess: () => setActiveTab('reports'), // Ensure we stay on reports tab
            preserveState: true, // Keep the active tab
            preserveScroll: true,
        });
    };

    const retryAllFailedJobs = () => {
        setRetryingFailedJobs(true);

        router.post(route('admin.queue.retry'), {}, {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => setActiveTab('system'),
            onFinish: () => setRetryingFailedJobs(false),
        });
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

    const openIpLookupModal = async (ipAddress) => {
        setIpLookupModal({
            show: true,
            loading: true,
            ip: ipAddress,
            data: null,
            error: null,
        });

        try {
            const response = await fetch(`/admin/ip-intelligence/${encodeURIComponent(ipAddress)}`, {
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

    const toggleTokenVisibility = (domainId) => {
        setRevealedTokens((current) => ({
            ...current,
            [domainId]: !current[domainId],
        }));
    };

    const rotateTier3Token = (domain) => {
        const confirmed = window.confirm(
            `Rotate the Tier 3 token for ${domain.domain}?\n\nThis will instantly disconnect the client's telemetry until the new token is deployed in the external application.`
        );

        if (!confirmed) {
            return;
        }

        setRotatingDomainId(domain.id);

        router.post(route('admin.domains.rotate-token', domain.id), {}, {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => setActiveTab('tier3'),
            onFinish: () => setRotatingDomainId(null),
        });
    };

    const toggleTier3DomainStatus = (domain) => {
        if (domain.is_active) {
            const confirmed = window.confirm(
                'Disabling this domain will immediately stop telemetry ingestion and blocklist access for this application.'
            );

            if (!confirmed) {
                return;
            }
        }

        setTogglingDomainId(domain.id);

        router.post(route('admin.domains.toggle-status', domain.id), {}, {
            preserveScroll: true,
            preserveState: true,
            onSuccess: () => setActiveTab('tier3'),
            onFinish: () => setTogglingDomainId(null),
        });
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Admin Console</h2>}
        >
            <Head title="Admin Dashboard" />

            <div className="flex min-h-screen w-full bg-gray-100">

                {/* --- SIDEBAR --- */}
                <aside className="w-1/5 bg-white border-r border-gray-200 min-h-screen">
                    <div className="p-6">
                        <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-4">Menu</h3>
                        <nav className="space-y-2">
                            <button
                                onClick={() => setActiveTab('threats')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'threats' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <LayoutDashboard className="w-5 h-5 mr-3" /> Threat Overview
                            </button>

                            <button
                                onClick={() => setActiveTab('users')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'users' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <Users className="w-5 h-5 mr-3" /> User Management
                            </button>

                            <Link
                                href={route('admin.blocked-ips.index')}
                                className="flex w-full items-center rounded-md px-4 py-3 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-50"
                            >
                                <ShieldAlert className="mr-3 h-5 w-5" /> Blocked IPs
                            </Link>

                            {/* 👇 NEW REPORTS TAB */}
                            <button
                                onClick={() => setActiveTab('reports')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'reports' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <FileText className="w-5 h-5 mr-3" /> Reports & Analytics
                            </button>

                            <button
                                onClick={() => setActiveTab('domains')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'domains' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <ShieldCheck className="w-5 h-5 mr-3" /> Whitelist Manager
                            </button>

                            <button
                                onClick={() => setActiveTab('system')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'system' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <Server className="w-5 h-5 mr-3" /> System Health
                            </button>

                            <button
                                onClick={() => setActiveTab('intelligence')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'intelligence' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <Globe2 className="w-5 h-5 mr-3" /> Global Intelligence
                            </button>

                            <button
                                onClick={() => setActiveTab('tier3')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'tier3' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <KeyRound className="w-5 h-5 mr-3" /> Tier 3 Tokens
                            </button>

                            <button
                                onClick={() => setActiveTab('audit')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'audit' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <History className="w-5 h-5 mr-3" /> Audit Trail
                            </button>
                        </nav>
                    </div>
                </aside>

                {/* --- MAIN CONTENT --- */}
                <main className="w-4/5 p-8">
                    {flash?.success && (
                        <div className="mb-6 flex items-center rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800 shadow-sm">
                            <CheckCircle className="mr-2 h-5 w-5 shrink-0" />
                            <span>{flash.success}</span>
                        </div>
                    )}

                    {flash?.error && (
                        <div className="mb-6 flex items-center rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 shadow-sm">
                            <AlertTriangle className="mr-2 h-5 w-5 shrink-0" />
                            <span>{flash.error}</span>
                        </div>
                    )}

                    {/* VIEW 1: THREATS */}
                    {/* VIEW 1: THREATS TABLE */}
                    {activeTab === 'threats' && (
                        <div className="space-y-6">
                            <div className="flex justify-between items-center">
                                <h3 className="text-2xl font-bold text-gray-800">
                                    <ShieldAlert className="inline-block w-8 h-8 mr-2 text-red-600" />
                                    Active Threat Alerts
                                </h3>
                            </div>

                            <div className="bg-white rounded-lg shadow overflow-hidden border border-gray-200">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Detected</th>
                                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {threats.length > 0 ? (
                                            threats.map((threat) => (
                                                <tr key={threat.id} className="hover:bg-gray-50 transition-colors">
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <span className={`px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full
                                                            ${threat.severity === 'high' ? 'bg-red-100 text-red-800' :
                                                              threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                                              'bg-blue-100 text-blue-800'}`}>
                                                            {threat.severity ? threat.severity.toUpperCase() : 'UNKNOWN'}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4">
                                                        <div className="text-sm font-medium text-gray-900 truncate max-w-xs" title={threat.subject}>
                                                            {threat.subject || 'No Subject'}
                                                        </div>
                                                        <div className="text-xs text-gray-500 truncate max-w-xs">
                                                            {threat.sender}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                        {threat.user ? threat.user.name : 'Unknown User'}
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                        {new Date(threat.created_at).toLocaleDateString()}
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                        <button
                                                            onClick={() => openThreatModal(threat)}
                                                            className="text-indigo-600 hover:text-indigo-900 bg-indigo-50 px-3 py-1 rounded-md transition-colors"
                                                        >
                                                            View Analysis
                                                        </button>
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="5" className="px-6 py-10 text-center text-gray-500">
                                                    <div className="flex flex-col items-center justify-center">
                                                        <CheckCircle className="w-12 h-12 text-green-400 mb-2" />
                                                        <p className="text-lg font-medium">No threats detected.</p>
                                                        <p className="text-sm">Your company is currently safe.</p>
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* VIEW 2: USERS */}
                    {/* VIEW 2: USERS TABLE */}
                    {activeTab === 'users' && (
                        <div className="space-y-6">
                            <div className="flex justify-between items-center">
                                <h3 className="text-2xl font-bold text-gray-800">
                                    <Users className="inline-block w-8 h-8 mr-2 text-blue-600" />
                                    Company Members
                                </h3>
                                <PrimaryButton onClick={() => setShowUserModal(true)}>
                                    <UserPlus className="w-4 h-4 mr-2" /> Add New User
                                </PrimaryButton>
                            </div>

                            <div className="bg-white rounded-lg shadow overflow-hidden border border-gray-200">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Joined</th>
                                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {users.length > 0 ? (
                                            users.map((user) => (
                                                <tr key={user.id} className="hover:bg-gray-50 transition-colors">
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <div className="flex items-center">
                                                            <div className="flex-shrink-0 h-10 w-10">
                                                                <div className="h-10 w-10 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600 font-bold text-lg">
                                                                    {user.name.charAt(0).toUpperCase()}
                                                                </div>
                                                            </div>
                                                            <div className="ml-4">
                                                                <div className="text-sm font-medium text-gray-900">{user.name}</div>
                                                                <div className="text-sm text-gray-500">{user.email}</div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                                                            ${user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-green-100 text-green-800'}`}>
                                                            {user.role ? user.role.toUpperCase() : 'USER'}
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                                                            Active
                                                        </span>
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                        {new Date(user.created_at).toLocaleDateString()}
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                        <button
                                                            onClick={() => openEditUserModal(user)}
                                                            className="text-indigo-600 hover:text-indigo-900"
                                                        >
                                                            Edit
                                                        </button>
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="5" className="px-6 py-10 text-center text-gray-500">
                                                    No users found in this company.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* 👇 VIEW 3: REPORTS */}
                    {activeTab === 'reports' && (
                        <div className="space-y-6">
                            <h3 className="text-2xl font-bold text-gray-800">Security Reports</h3>

                            {/* 1. Date Selection Form */}
                            <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                                <h4 className="text-md font-semibold text-gray-700 mb-4 flex items-center">
                                    <Calendar className="w-4 h-4 mr-2" /> Generate New Report
                                </h4>
                                <form onSubmit={submitReport} className="flex gap-4 items-end">
                                    <div className="flex-1">
                                        <InputLabel value="Start Date" />
                                        <TextInput
                                            type="date"
                                            className="w-full mt-1"
                                            value={reportForm.data.start_date}
                                            onChange={e => reportForm.setData('start_date', e.target.value)}
                                        />
                                        <InputError message={reportForm.errors.start_date} />
                                    </div>
                                    <div className="flex-1">
                                        <InputLabel value="End Date" />
                                        <TextInput
                                            type="date"
                                            className="w-full mt-1"
                                            value={reportForm.data.end_date}
                                            onChange={e => reportForm.setData('end_date', e.target.value)}
                                        />
                                        <InputError message={reportForm.errors.end_date} />
                                    </div>
                                    <PrimaryButton disabled={reportForm.processing}>
                                        Generate Analysis
                                    </PrimaryButton>
                                </form>
                            </div>

                            {/* 2. Report Results (Only show if data exists) */}
                            {reportData && (
                                <div className="space-y-6 animate-fade-in">
                                    <div className="flex items-center justify-between">
                                        <h4 className="text-lg font-bold text-gray-600">
                                            Results for: <span className="text-indigo-600">{reportData.date_range}</span>
                                        </h4>
                                    </div>

                                    {/* Stats Cards */}
                                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                                        {/* Protection Score */}
                                        <div className="bg-gradient-to-br from-indigo-500 to-purple-600 p-4 rounded-lg text-white shadow">
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className="text-indigo-100 text-sm font-medium">Protection Score</p>
                                                    <p className="text-3xl font-bold mt-1">{reportData.protection_score}%</p>
                                                </div>
                                                <TrendingUp className="w-8 h-8 text-indigo-200 opacity-50" />
                                            </div>
                                            <p className="text-xs mt-2 text-indigo-100 opacity-80">Based on threats neutralized</p>
                                        </div>

                                        {/* Total Emails */}
                                        <div className="bg-white p-4 rounded-lg shadow border border-gray-100">
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className="text-gray-500 text-sm font-medium">Emails Scanned</p>
                                                    <p className="text-2xl font-bold text-gray-800 mt-1">{reportData.email_stats.total}</p>
                                                </div>
                                                <Mail className="w-6 h-6 text-blue-500 bg-blue-50 p-1 rounded" />
                                            </div>
                                            <div className="mt-2 text-xs flex gap-3">
                                                <span className="text-red-500 font-semibold">{reportData.email_stats.threats} Threats</span>
                                                <span className="text-green-600 font-semibold">{reportData.email_stats.verified_safe} Verified Safe</span>
                                            </div>
                                        </div>

                                        {/* Total SMS */}
                                        <div className="bg-white p-4 rounded-lg shadow border border-gray-100">
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className="text-gray-500 text-sm font-medium">SMS Scanned</p>
                                                    <p className="text-2xl font-bold text-gray-800 mt-1">{reportData.sms_stats.total}</p>
                                                </div>
                                                <Smartphone className="w-6 h-6 text-purple-500 bg-purple-50 p-1 rounded" />
                                            </div>
                                            <div className="mt-2 text-xs text-red-500 font-semibold">
                                                {reportData.sms_stats.threats} Threats Detected
                                            </div>
                                        </div>
                                    </div>

                                    {/* User Breakdown Table */}
                                    <div className="bg-white rounded-lg shadow border border-gray-200 overflow-hidden">
                                        <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
                                            <h5 className="font-semibold text-gray-700">Email Scanning Activity by User</h5>
                                        </div>
                                        <table className="min-w-full divide-y divide-gray-200">
                                            <thead className="bg-gray-50">
                                                <tr>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">User Name</th>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Emails Scanned</th>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Activity Share</th>
                                                </tr>
                                            </thead>
                                            <tbody className="bg-white divide-y divide-gray-200">
                                                {reportData.user_breakdown.length > 0 ? (
                                                    reportData.user_breakdown.map((stat, idx) => (
                                                        <tr key={idx}>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                                {stat.name}
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                                {stat.email_count}
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                                <div className="w-full bg-gray-200 rounded-full h-1.5 max-w-[100px]">
                                                                    <div
                                                                        className="bg-blue-500 h-1.5 rounded-full"
                                                                        style={{ width: `${(stat.email_count / reportData.email_stats.total) * 100}%` }}
                                                                    ></div>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="3" className="px-6 py-4 text-center text-sm text-gray-400">
                                                            No user activity found in this period.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                    {activeTab === 'domains' && (
                        <DomainManagerTab domains={domains} />
                    )}
                    {activeTab === 'intelligence' && (
                        <div className="space-y-6">
                            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                                <div>
                                    <h3 className="text-2xl font-bold text-gray-800">
                                        <Globe2 className="inline-block w-8 h-8 mr-2 text-indigo-600" />
                                        Global Intelligence
                                    </h3>
                                    <p className="mt-1 text-sm text-gray-500">
                                        Cross-tenant threat telemetry aggregated from the shared security event stream.
                                    </p>
                                </div>

                                <a
                                    href={route('admin.threats.export')}
                                    download
                                    className="inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700"
                                >
                                    <Download className="mr-2 h-4 w-4" />
                                    Export Global Threat Feed (JSON)
                                </a>
                            </div>

                            <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                                <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow">
                                    <div className="border-b border-gray-100 bg-gray-50 px-6 py-4">
                                        <h4 className="text-base font-semibold text-gray-900">Top Targeted Paths</h4>
                                        <p className="mt-1 text-sm text-gray-500">
                                            Most frequently probed routes across the global threat log.
                                        </p>
                                    </div>

                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200">
                                            <thead className="bg-gray-50">
                                                <tr>
                                                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Path</th>
                                                    <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider text-gray-500">Hits</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-200 bg-white">
                                                {top_targeted_paths.length > 0 ? (
                                                    top_targeted_paths.map((item, index) => (
                                                        <tr key={`${item.path_targeted}-${index}`} className="hover:bg-gray-50 transition-colors">
                                                            <td className="px-6 py-4 text-sm font-medium text-gray-900">
                                                                <span className="rounded bg-gray-100 px-2 py-1 font-mono text-xs text-gray-700">
                                                                    {item.path_targeted}
                                                                </span>
                                                            </td>
                                                            <td className="px-6 py-4 text-right text-sm font-semibold text-gray-700">
                                                                {item.count}
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="2" className="px-6 py-10 text-center text-sm text-gray-500">
                                                            No targeted path data available yet.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow">
                                    <div className="border-b border-gray-100 bg-gray-50 px-6 py-4">
                                        <h4 className="text-base font-semibold text-gray-900">Top Attacker IPs</h4>
                                        <p className="mt-1 text-sm text-gray-500">
                                            Highest-volume source IPs observed across recent shared telemetry.
                                        </p>
                                    </div>

                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200">
                                            <thead className="bg-gray-50">
                                                <tr>
                                                    <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Attacker IP</th>
                                                    <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider text-gray-500">Events</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-gray-200 bg-white">
                                                {top_attacker_ips.length > 0 ? (
                                                    top_attacker_ips.map((item, index) => (
                                                        <tr key={`${item.attacker_ip}-${index}`} className="hover:bg-gray-50 transition-colors">
                                                            <td className="px-6 py-4 text-sm font-medium text-gray-900">
                                                                <button
                                                                    type="button"
                                                                    onClick={() => openIpLookupModal(item.attacker_ip)}
                                                                    className="rounded bg-red-50 px-2 py-1 font-mono text-xs text-blue-600 transition hover:underline"
                                                                >
                                                                    {item.attacker_ip}
                                                                </button>
                                                            </td>
                                                            <td className="px-6 py-4 text-right text-sm font-semibold text-gray-700">
                                                                {item.count}
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="2" className="px-6 py-10 text-center text-sm text-gray-500">
                                                            No attacker IP data available yet.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    {activeTab === 'tier3' && (
                        <div className="space-y-6">
                            <div>
                                <h3 className="text-2xl font-bold text-gray-800">
                                    <KeyRound className="inline-block w-8 h-8 mr-2 text-indigo-600" />
                                    Tier 3 Tokens
                                </h3>
                                <p className="mt-1 text-sm text-gray-500">
                                    Oversee application-middleware credentials and ingestion load for external telemetry clients.
                                </p>
                            </div>

                            <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow">
                                <div className="border-b border-gray-100 bg-gray-50 px-6 py-4">
                                    <h4 className="text-base font-semibold text-gray-900">App Middleware Domain Tokens</h4>
                                    <p className="mt-1 text-sm text-gray-500">
                                        Rotating a token invalidates the current client secret immediately.
                                    </p>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-200">
                                        <thead className="bg-gray-50">
                                            <tr>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Domain Name</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Status</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Log Count</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Token</th>
                                                <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider text-gray-500">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-200 bg-white">
                                            {tier_3_domains.length > 0 ? (
                                                tier_3_domains.map((domain) => {
                                                    const isRevealed = Boolean(revealedTokens[domain.id]);
                                                    const isRotating = rotatingDomainId === domain.id;
                                                    const isToggling = togglingDomainId === domain.id;

                                                    return (
                                                        <tr key={domain.id} className="hover:bg-gray-50 transition-colors">
                                                            <td className="px-6 py-4 align-top">
                                                                <div className="text-sm font-semibold text-gray-900">{domain.domain}</div>
                                                                <div className="mt-1 text-xs text-gray-500">
                                                                    Infrastructure: Application Middleware (Tier 3)
                                                                </div>
                                                            </td>
                                                            <td className="px-6 py-4 align-top">
                                                                <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${
                                                                    domain.is_active
                                                                        ? 'bg-emerald-50 text-emerald-700'
                                                                        : 'bg-gray-200 text-gray-700'
                                                                }`}>
                                                                    {domain.is_active ? 'Active' : 'Disabled'}
                                                                </span>
                                                            </td>
                                                            <td className="px-6 py-4 align-top">
                                                                <span className="inline-flex rounded-full bg-indigo-50 px-3 py-1 text-xs font-semibold text-indigo-700">
                                                                    {domain.security_threat_logs_count ?? 0} logs
                                                                </span>
                                                            </td>
                                                            <td className="px-6 py-4 align-top">
                                                                <div className="flex flex-col gap-2">
                                                                    <code className="inline-block max-w-md break-all rounded bg-gray-100 px-3 py-2 text-xs text-gray-700">
                                                                        {isRevealed ? (domain.app_secret_token || 'No token provisioned') : maskToken(domain.app_secret_token)}
                                                                    </code>
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => toggleTokenVisibility(domain.id)}
                                                                        className="inline-flex w-fit items-center text-xs font-medium text-indigo-600 hover:text-indigo-700"
                                                                    >
                                                                        {isRevealed ? (
                                                                            <>
                                                                                <EyeOff className="mr-1 h-3.5 w-3.5" />
                                                                                Hide token
                                                                            </>
                                                                        ) : (
                                                                            <>
                                                                                <Eye className="mr-1 h-3.5 w-3.5" />
                                                                                Click to reveal
                                                                            </>
                                                                        )}
                                                                    </button>
                                                                </div>
                                                            </td>
                                                            <td className="px-6 py-4 align-top text-right">
                                                                <div className="flex justify-end gap-2">
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => toggleTier3DomainStatus(domain)}
                                                                        disabled={isToggling || isRotating}
                                                                        className={`inline-flex items-center rounded-md border px-3 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${
                                                                            domain.is_active
                                                                                ? 'border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100'
                                                                                : 'border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100'
                                                                        }`}
                                                                    >
                                                                        <RefreshCw className={`mr-2 h-4 w-4 ${isToggling ? 'animate-spin' : ''}`} />
                                                                        {domain.is_active ? 'Disable' : 'Enable'}
                                                                    </button>
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => rotateTier3Token(domain)}
                                                                        disabled={isRotating || isToggling}
                                                                        className="inline-flex items-center rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                                                                    >
                                                                        <RefreshCw className={`mr-2 h-4 w-4 ${isRotating ? 'animate-spin' : ''}`} />
                                                                        Rotate Token
                                                                    </button>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    );
                                                })
                                            ) : (
                                                <tr>
                                                    <td colSpan="5" className="px-6 py-10 text-center text-sm text-gray-500">
                                                        No Tier 3 middleware domains have been provisioned yet.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                    {activeTab === 'audit' && (
                        <div className="space-y-6">
                            <div>
                                <h3 className="text-2xl font-bold text-gray-800">
                                    <History className="inline-block w-8 h-8 mr-2 text-indigo-600" />
                                    Audit Trail
                                </h3>
                                <p className="mt-1 text-sm text-gray-500">
                                    Recent administrative actions and system-level control changes across the SOC platform.
                                </p>
                            </div>

                            <div className="overflow-hidden rounded-lg border border-gray-200 bg-white shadow">
                                <div className="border-b border-gray-100 bg-gray-50 px-6 py-4">
                                    <h4 className="text-base font-semibold text-gray-900">Latest Activity Logs</h4>
                                    <p className="mt-1 text-sm text-gray-500">
                                        The 50 most recent recorded admin and system actions.
                                    </p>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-200">
                                        <thead className="bg-gray-50">
                                            <tr>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Timestamp</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">User</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Action</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">Target</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-200 bg-white">
                                            {audit_logs.length > 0 ? (
                                                audit_logs.map((log) => (
                                                    <tr key={log.id} className="hover:bg-gray-50 transition-colors">
                                                        <td className="px-6 py-4 align-top text-sm text-gray-600">
                                                            {log.created_at ? new Date(log.created_at).toLocaleString() : 'Unknown'}
                                                        </td>
                                                        <td className="px-6 py-4 align-top">
                                                            <div className="text-sm font-medium text-gray-900">
                                                                {getAuditActorLabel(log.user)}
                                                            </div>
                                                            {log.user?.email && (
                                                                <div className="mt-1 text-xs text-gray-500">
                                                                    {log.user.email}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-6 py-4 align-top">
                                                            <div className="text-sm font-semibold text-gray-900">
                                                                {formatAuditAction(log.action)}
                                                            </div>
                                                            {log.metadata?.domain && (
                                                                <div className="mt-1 text-xs text-gray-500">
                                                                    Domain: {log.metadata.domain}
                                                                </div>
                                                            )}
                                                        </td>
                                                        <td className="px-6 py-4 align-top text-sm text-gray-600">
                                                            {log.target_type && log.target_id ? (
                                                                <span className="inline-flex rounded bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700">
                                                                    {log.target_type} #{log.target_id}
                                                                </span>
                                                            ) : (
                                                                'System-wide'
                                                            )}
                                                        </td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan="4" className="px-6 py-10 text-center text-sm text-gray-500">
                                                        No audit activity has been recorded yet.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                    {activeTab === 'system' && (
                        <div className="space-y-6">
                            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                <div>
                                    <h3 className="text-2xl font-bold text-gray-800">
                                        <Server className="inline-block w-8 h-8 mr-2 text-indigo-600" />
                                        System Health &amp; Background Workers
                                    </h3>
                                    <p className="mt-1 text-sm text-gray-500">
                                        Monitor queue depth, failed job backlog, and recent worker crashes across the platform.
                                    </p>
                                </div>

                                {failed_jobs_count > 0 && (
                                    <PrimaryButton onClick={retryAllFailedJobs} disabled={retryingFailedJobs}>
                                        <RefreshCw className={`w-4 h-4 mr-2 ${retryingFailedJobs ? 'animate-spin' : ''}`} />
                                        Retry All Failed Jobs
                                    </PrimaryButton>
                                )}
                            </div>

                            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                <div className="rounded-lg border border-blue-100 bg-white p-5 shadow-sm">
                                    <div className="flex items-start justify-between">
                                        <div>
                                            <p className="text-sm font-medium text-gray-500">Pending Jobs</p>
                                            <p className="mt-2 text-3xl font-bold text-gray-900">{pending_jobs_count}</p>
                                            <p className="mt-2 text-xs text-gray-500">Jobs currently waiting in the database queue.</p>
                                        </div>
                                        <div className="rounded-full bg-blue-50 p-2 text-blue-600">
                                            <RefreshCw className="w-6 h-6" />
                                        </div>
                                    </div>
                                </div>

                                <div className="rounded-lg border border-red-100 bg-white p-5 shadow-sm">
                                    <div className="flex items-start justify-between">
                                        <div>
                                            <p className="text-sm font-medium text-gray-500">Failed Jobs</p>
                                            <p className="mt-2 text-3xl font-bold text-gray-900">{failed_jobs_count}</p>
                                            <p className="mt-2 text-xs text-gray-500">Failed worker executions recorded by Laravel.</p>
                                        </div>
                                        <div className="rounded-full bg-red-50 p-2 text-red-600">
                                            <AlertTriangle className="w-6 h-6" />
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="bg-white rounded-lg shadow overflow-hidden border border-gray-200">
                                <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
                                    <h4 className="font-semibold text-gray-800">Recent Failed Jobs</h4>
                                    <p className="mt-1 text-sm text-gray-500">
                                        Five most recent job failures captured from the failed jobs store.
                                    </p>
                                </div>

                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-200">
                                        <thead className="bg-gray-50">
                                            <tr>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Job</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Queue</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Failed At</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Exception</th>
                                            </tr>
                                        </thead>
                                        <tbody className="bg-white divide-y divide-gray-200">
                                            {recent_failed_jobs.length > 0 ? (
                                                recent_failed_jobs.map((job) => (
                                                    <tr key={job.id} className="hover:bg-gray-50 transition-colors">
                                                        <td className="px-6 py-4 align-top">
                                                            <div className="text-sm font-semibold text-gray-900">
                                                                {getFailedJobDisplayName(job.payload)}
                                                            </div>
                                                            <div className="mt-1 text-xs text-gray-500">
                                                                Failed Job ID #{job.id}
                                                            </div>
                                                        </td>
                                                        <td className="px-6 py-4 align-top text-sm text-gray-600">
                                                            {job.queue || 'default'}
                                                        </td>
                                                        <td className="px-6 py-4 align-top text-sm text-gray-600">
                                                            {job.failed_at ? new Date(job.failed_at).toLocaleString() : 'Unknown'}
                                                        </td>
                                                        <td className="px-6 py-4 align-top">
                                                            <p className="max-w-xl text-sm text-gray-600" title={job.exception}>
                                                                {truncateText(job.exception, 220)}
                                                            </p>
                                                        </td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan="4" className="px-6 py-10 text-center text-gray-500">
                                                        <div className="flex flex-col items-center justify-center">
                                                            <CheckCircle className="w-12 h-12 text-green-400 mb-2" />
                                                            <p className="text-lg font-medium">No failed jobs recorded.</p>
                                                            <p className="text-sm">Background workers are currently healthy.</p>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}
                </main>
            </div>

            {/* Modals (Keep existing modals here) */}
            <ThreatDetailModal
                show={showThreatModal}
                onClose={() => setShowThreatModal(false)}
                email={selectedThreat}
            />

            <IpIntelligenceModal state={ipLookupModal} onClose={closeIpLookupModal} />

            <Modal show={showUserModal} onClose={() => setShowUserModal(false)} maxWidth="md">
                <div className="p-6">
                    <h2 className="text-lg font-medium text-gray-900">Add New User</h2>

                    <form onSubmit={submitUser} className="mt-4">
                        {/* Name Field */}
                        <div>
                            <InputLabel htmlFor="name" value="Name" />
                            <TextInput
                                id="name"
                                type="text"
                                name="name"
                                value={data.name}
                                className="mt-1 block w-full"
                                isFocused={true}
                                onChange={(e) => setData('name', e.target.value)}
                                required
                            />
                            <InputError message={errors.name} className="mt-2" />
                        </div>

                        {/* Email Field */}
                        <div className="mt-4">
                            <InputLabel htmlFor="email" value="Email Address" />
                            <TextInput
                                id="email"
                                type="email"
                                name="email"
                                value={data.email}
                                className="mt-1 block w-full"
                                onChange={(e) => setData('email', e.target.value)}
                                required
                            />
                            <InputError message={errors.email} className="mt-2" />
                        </div>

                        {/* Submit & Cancel Buttons */}
                        <div className="flex justify-end mt-6">
                            <SecondaryButton onClick={() => setShowUserModal(false)} className="mr-3">
                                Cancel
                            </SecondaryButton>
                            <PrimaryButton disabled={processing}>
                                Create User
                            </PrimaryButton>
                        </div>
                    </form>
                </div>
            </Modal>
            <Modal show={showEditUserModal} onClose={() => setShowEditUserModal(false)} maxWidth="md">
                <div className="p-6">
                    <h2 className="text-lg font-medium text-gray-900">Edit User: {editingUser?.name}</h2>

                    <form onSubmit={submitEditUser} className="mt-4">
                        {/* Name */}
                        <div>
                            <InputLabel htmlFor="edit_name" value="Name" />
                            <TextInput
                                id="edit_name"
                                type="text"
                                value={editForm.data.name}
                                className="mt-1 block w-full"
                                onChange={(e) => editForm.setData('name', e.target.value)}
                                required
                            />
                            <InputError message={editForm.errors.name} className="mt-2" />
                        </div>

                        {/* Email */}
                        <div className="mt-4">
                            <InputLabel htmlFor="edit_email" value="Email Address" />
                            <TextInput
                                id="edit_email"
                                type="email"
                                value={editForm.data.email}
                                className="mt-1 block w-full"
                                onChange={(e) => editForm.setData('email', e.target.value)}
                                required
                            />
                            <InputError message={editForm.errors.email} className="mt-2" />
                        </div>

                        {/* Role */}
                        <div className="mt-4">
                            <InputLabel htmlFor="edit_role" value="User Role" />
                            <select
                                id="edit_role"
                                value={editForm.data.role}
                                onChange={(e) => editForm.setData('role', e.target.value)}
                                className="mt-1 block w-full border-gray-300 focus:border-indigo-500 focus:ring-indigo-500 rounded-md shadow-sm"
                            >
                                <option value="user">Standard User</option>
                                <option value="admin">Administrator</option>
                            </select>
                            <InputError message={editForm.errors.role} className="mt-2" />
                        </div>

                        {/* Password (Optional) */}
                        <div className="mt-4">
                            <InputLabel htmlFor="edit_password" value="New Password (leave blank to keep current)" />
                            <TextInput
                                id="edit_password"
                                type="password"
                                value={editForm.data.password}
                                className="mt-1 block w-full"
                                onChange={(e) => editForm.setData('password', e.target.value)}
                            />
                            <InputError message={editForm.errors.password} className="mt-2" />
                        </div>

                        <div className="flex justify-end mt-6">
                            <SecondaryButton onClick={() => setShowEditUserModal(false)} className="mr-3">
                                Cancel
                            </SecondaryButton>
                            <PrimaryButton disabled={editForm.processing}>
                                Save Changes
                            </PrimaryButton>
                        </div>
                    </form>
                </div>
            </Modal>
        </AuthenticatedLayout>
    );
}
