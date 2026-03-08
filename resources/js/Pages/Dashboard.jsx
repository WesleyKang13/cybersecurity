import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage, Link, useForm, router } from '@inertiajs/react';
import { ShieldAlert, ShieldCheck, Mail, Smartphone, Plus, CheckCircle, XCircle, LogOut, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { useState, useEffect } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';

export default function Dashboard({ auth, initialStats, isConnected, recentAlerts, filter }) {
    const { flash } = usePage().props;
    const { post } = useForm();

    const statsData = initialStats || { emails_scanned: 0, sms_scanned: 0, threats: 0, protected: 1 };

    const [selectedEmail, setSelectedEmail] = useState(null);
    const [showModal, setShowModal] = useState(false);

    // --- DATATABLE STATE ---
    const [searchTerm, setSearchTerm] = useState('');
    const [currentPage, setCurrentPage] = useState(1);
    // 👇 Now a state variable so the user can change it
    const [itemsPerPage, setItemsPerPage] = useState(50);

    // --- AUTO REFRESH LOGIC ---
    useEffect(() => {
        const interval = setInterval(() => {
            router.reload({
                only: ['recentAlerts', 'initialStats'],
                preserveState: true,
                preserveScroll: true,
            });
        }, 60000);
        return () => clearInterval(interval);
    }, []);

    // --- RESET PAGINATION ON SEARCH OR ROW COUNT CHANGE ---
    useEffect(() => {
        setCurrentPage(1);
    }, [searchTerm, itemsPerPage]);

    // --- DATATABLE LOGIC (FILTERING & PAGINATION) ---
    const filteredAlerts = (recentAlerts || []).filter((alert) => {
        if (!searchTerm) return true;
        const searchLower = searchTerm.toLowerCase();
        return (
            (alert.subject && alert.subject.toLowerCase().includes(searchLower)) ||
            (alert.sender && alert.sender.toLowerCase().includes(searchLower)) ||
            (alert.source && alert.source.toLowerCase().includes(searchLower))
        );
    });

    const totalPages = Math.ceil(filteredAlerts.length / itemsPerPage);
    const paginatedAlerts = filteredAlerts.slice(
        (currentPage - 1) * itemsPerPage,
        currentPage * itemsPerPage
    );

    const handleRowClick = (alert) => {
        if (alert.source === 'email') {
            setSelectedEmail(alert);
            setShowModal(true);
        }
    };

    const closeModal = () => {
        setShowModal(false);
        setTimeout(() => setSelectedEmail(null), 300);
    };

    const handleDisconnect = () => {
        if (confirm('Are you sure you want to disconnect? Your emails will not be scanned once disconnected')) {
            post(route('google.disconnect'));
        }
    };

    const handleMarkSafe = (id, source) => {
        if (confirm("Mark this item as safe? It will be removed from the threat list.")) {
            router.post(route('scan.mark-safe', { id, source }));
        }
    };

    const handleDelete = (id, source) => {
        if (confirm("Note: This will only remove the email from your dashboard and not in your gmail inbox. Proceed to delete?")) {
            router.delete(route('scan.delete', { id, source }));
        }
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Dashboard</h2>}
        >
            <Head title="Dashboard" />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-6">

                    {/* Flash Messages */}
                    {flash.success && (
                        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded flex items-center">
                            <CheckCircle className="w-5 h-5 mr-2" />
                            <span>{flash.success}</span>
                        </div>
                    )}

                    {/* Connection Status Bar */}
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-l-4 border-indigo-500 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 flex items-center gap-2">
                                {isConnected ? 'Workspace Active' : 'Limited Protection'}
                                {/* 👇 Auto-Quarantine Badge */}
                                {isConnected && auth.user.auto_quarantine && (
                                    <span className="bg-red-100 text-red-800 text-xs font-bold px-2 py-0.5 rounded uppercase tracking-wide">
                                        Active Defense ON
                                    </span>
                                )}
                            </h3>
                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                {isConnected
                                    ? 'System is currently monitoring your Emails and SMS.'
                                    : 'Connect Google Workspace to enable Email scanning. SMS scanning is active.'}
                            </p>
                        </div>
                        <div className="flex items-center gap-4">
                            {/* 👇 The Kill Switch (Only show if connected) */}
                            {isConnected && (
                                <label className="flex items-center cursor-pointer">
                                    <div className="relative">
                                        <input
                                            type="checkbox"
                                            className="sr-only"
                                            checked={auth.user.auto_quarantine}
                                            onChange={(e) => {
                                                if(confirm(e.target.checked ? "Enable Active Defense? High-risk emails will be moved to SPAM automatically." : "Disable Active Defense?")) {
                                                    router.post(route('settings.quarantine.toggle'), { auto_quarantine: e.target.checked }, { preserveScroll: true });
                                                }
                                            }}
                                        />
                                        <div className={`block w-14 h-8 rounded-full transition-colors ${auth.user.auto_quarantine ? 'bg-red-500' : 'bg-gray-300 dark:bg-gray-600'}`}></div>
                                        <div className={`dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition-transform ${auth.user.auto_quarantine ? 'transform translate-x-6' : ''}`}></div>
                                    </div>
                                    <div className="ml-3 text-sm font-medium text-gray-700 dark:text-gray-300">
                                        Auto-Quarantine
                                    </div>
                                </label>
                            )}

                            {!isConnected ? (
                                <a href={route('google.connect')} className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-500 transition">
                                    <Plus className="w-4 h-4 mr-2" /> Connect Google
                                </a>
                            ) : (
                                <button onClick={handleDisconnect} className="inline-flex items-center px-4 py-2 bg-red-100 border border-transparent rounded-md font-semibold text-xs text-red-700 uppercase tracking-widest hover:bg-red-200 transition">
                                    <LogOut className="w-4 h-4 mr-2" /> Disconnect
                                </button>
                            )}
                        </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                        <Link href={route('dashboard', { filter: 'email' })} className={`bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-2 transition duration-200 ${filter === 'email' ? 'border-blue-500' : 'border-transparent hover:border-blue-200'}`}>
                            <div className="flex items-center">
                                <div className="p-3 rounded-full bg-blue-100 text-blue-600">
                                    <Mail className="h-6 w-6" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Emails Scanned</p>
                                    <p className="text-2xl font-semibold text-gray-900 dark:text-gray-100">{statsData.emails_scanned}</p>
                                </div>
                            </div>
                        </Link>

                        <Link href={route('dashboard', { filter: 'sms' })} className={`bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-2 transition duration-200 ${filter === 'sms' ? 'border-purple-500' : 'border-transparent hover:border-purple-200'}`}>
                            <div className="flex items-center">
                                <div className="p-3 rounded-full bg-purple-100 text-purple-600">
                                    <Smartphone className="h-6 w-6" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500 dark:text-gray-400">SMS Scanned</p>
                                    <p className="text-2xl font-semibold text-gray-900 dark:text-gray-100">{statsData.sms_scanned}</p>
                                </div>
                            </div>
                        </Link>

                        <Link href={route('dashboard', { filter: 'threats' })} className={`bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-2 transition duration-200 ${filter === 'threats' ? 'border-red-500' : 'border-transparent hover:border-red-200'}`}>
                            <div className="flex items-center">
                                <div className="p-3 rounded-full bg-red-100 text-red-600">
                                    <ShieldAlert className="h-6 w-6" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Threats Detected</p>
                                    <p className="text-2xl font-semibold text-gray-900 dark:text-gray-100">{statsData.threats}</p>
                                </div>
                            </div>
                        </Link>

                        <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-2 border-transparent">
                            <div className="flex items-center">
                                <div className="p-3 rounded-full bg-green-100 text-green-600">
                                    <ShieldCheck className="h-6 w-6" />
                                </div>
                                <div className="ml-4">
                                    <p className="text-sm font-medium text-gray-500 dark:text-gray-400">Protected Users</p>
                                    <p className="text-2xl font-semibold text-gray-900 dark:text-gray-100">{statsData.protected}</p>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Recent Activity Table */}
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg">
                        <div className="p-6 text-gray-900 dark:text-gray-100">

                            {/* Header, Rows Selector & Search Bar */}
                            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
                                <div className="flex items-center gap-4">
                                    <h3 className="text-lg font-medium">Recent Activity Log</h3>
                                    {filter !== 'all' && (
                                        <Link href={route('dashboard')} className="text-sm text-blue-600 hover:underline">
                                            Clear Filter
                                        </Link>
                                    )}
                                </div>

                                <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto">
                                    {/* 👇 Items Per Page Dropdown */}
                                    <div className="flex items-center gap-2 w-full sm:w-auto justify-end sm:justify-start">
                                        <label htmlFor="perPage" className="text-sm text-gray-500 dark:text-gray-400 whitespace-nowrap">Show:</label>
                                        <select
                                            id="perPage"
                                            value={itemsPerPage}
                                            onChange={(e) => setItemsPerPage(Number(e.target.value))}
                                            className="block w-20 py-1.5 pl-3 pr-8 border border-gray-300 rounded-md leading-5 bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            <option value={10}>10</option>
                                            <option value={25}>25</option>
                                            <option value={50}>50</option>
                                            <option value={100}>100</option>
                                        </select>
                                    </div>

                                    {/* Search Input */}
                                    <div className="relative w-full sm:w-72">
                                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                            <Search className="h-4 w-4 text-gray-400" />
                                        </div>
                                        <input
                                            type="text"
                                            placeholder="Search subject or sender..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="block w-full pl-10 pr-3 py-1.5 border border-gray-300 rounded-md leading-5 bg-white dark:bg-gray-700 dark:border-gray-600 dark:text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm transition-colors"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="overflow-x-auto border rounded-lg border-gray-200 dark:border-gray-700">
                                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                    <thead className="bg-gray-50 dark:bg-gray-700/50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject / Content</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                            {filter === 'threats' && (
                                                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                            )}
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                        {paginatedAlerts.length > 0 ? (
                                            paginatedAlerts.map((alert) => (
                                                <tr
                                                    key={alert.id}
                                                    onClick={() => handleRowClick(alert)}
                                                    className={`hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-150 ${alert.source === 'email' ? 'cursor-pointer' : ''}`}
                                                >
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        {alert.source === 'email' ? (
                                                            <span className="flex items-center gap-2 text-blue-600 bg-blue-50 px-2 py-1 rounded text-xs font-bold uppercase">
                                                                <Mail className="w-4 h-4" /> Email
                                                            </span>
                                                        ) : (
                                                            <span className="flex items-center gap-2 text-purple-600 bg-purple-50 px-2 py-1 rounded text-xs font-bold uppercase">
                                                                <Smartphone className="w-4 h-4" /> SMS
                                                            </span>
                                                        )}
                                                    </td>

                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                            alert.is_threat ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                                                        }`}>
                                                            {alert.is_threat ? 'THREAT' : 'SAFE'}
                                                        </span>

                                                        {alert.is_quarantined && (
                                                            <span
                                                                className="px-3 ms-1 py-1 inline-flex items-center gap-2 text-[10px] leading-4 font-bold rounded bg-orange-100 text-orange-800 border border-orange-200 uppercase tracking-wider shadow-sm"
                                                                title="This email was automatically moved to the SPAM folder."
                                                            >
                                                                🛡️ Quarantined
                                                            </span>
                                                        )}
                                                    </td>

                                                    <td className="px-6 py-4 whitespace-nowrap align-middle">
                                                        <div className="w-24">
                                                            <div className="flex justify-between text-xs mb-1">
                                                                <span className="font-bold text-gray-600 dark:text-gray-400">{alert.risk_score}% - {alert.severity.toUpperCase()}</span>
                                                            </div>
                                                            <div className="w-full bg-gray-200 rounded-full h-1.5 dark:bg-gray-700">
                                                                <div className={`h-1.5 rounded-full ${
                                                                    alert.risk_score > 75 ? 'bg-red-500' :
                                                                    alert.risk_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                                                                }`} style={{ width: `${alert.risk_score}%` }}></div>
                                                            </div>
                                                        </div>
                                                    </td>

                                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-300 max-w-xs truncate">
                                                        <span className="block font-medium text-gray-900 dark:text-gray-100">{alert.subject}</span>
                                                        <span className="text-xs text-gray-400">{alert.sender}</span>
                                                    </td>

                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                        {alert.date}
                                                    </td>

                                                    {filter === 'threats' && (
                                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                            {alert.is_threat && (
                                                                <>
                                                                    <button
                                                                        onClick={(e) => { e.stopPropagation(); handleMarkSafe(alert.id, alert.source); }}
                                                                        className="text-green-600 hover:text-green-900 mr-3"
                                                                        title="Mark as Safe"
                                                                    >
                                                                        <CheckCircle className="w-5 h-5" />
                                                                    </button>
                                                                    <button
                                                                        onClick={(e) => { e.stopPropagation(); handleDelete(alert.id, alert.source); }}
                                                                        className="text-gray-400 hover:text-gray-600"
                                                                        title="Dismiss Alert"
                                                                    >
                                                                        <XCircle className="w-5 h-5" />
                                                                    </button>
                                                                </>
                                                            )}
                                                        </td>
                                                    )}
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="6" className="px-6 py-8 text-center text-sm text-gray-500 dark:text-gray-400">
                                                    {searchTerm ? 'No activity matches your search.' : 'No activity found.'}
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>

                            {/* 👇 Pagination Controls */}
                            <div className="flex flex-col sm:flex-row items-center justify-between border-t border-gray-200 dark:border-gray-700 mt-4 pt-4 gap-4">
                                <div className="text-sm text-gray-700 dark:text-gray-300">
                                    {filteredAlerts.length === 0 ? (
                                        <span>Showing <span className="font-medium">0</span> to <span className="font-medium">0</span> of <span className="font-medium">0</span> results</span>
                                    ) : (
                                        <span>Showing <span className="font-medium">{((currentPage - 1) * itemsPerPage) + 1}</span> to <span className="font-medium">{Math.min(currentPage * itemsPerPage, filteredAlerts.length)}</span> of <span className="font-medium">{filteredAlerts.length}</span> results</span>
                                    )}
                                </div>

                                {totalPages > 1 && (
                                    <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                                        <button
                                            onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                                            disabled={currentPage === 1}
                                            className="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-gray-800 dark:border-gray-600"
                                        >
                                            <span className="sr-only">Previous</span>
                                            <ChevronLeft className="h-5 w-5" />
                                        </button>
                                        <div className="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300">
                                            Page {currentPage} of {totalPages}
                                        </div>
                                        <button
                                            onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                                            disabled={currentPage === totalPages}
                                            className="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed dark:bg-gray-800 dark:border-gray-600"
                                        >
                                            <span className="sr-only">Next</span>
                                            <ChevronRight className="h-5 w-5" />
                                        </button>
                                    </nav>
                                )}
                            </div>

                        </div>
                    </div>
                </div>
            </div>

            <ThreatDetailModal
                show={showModal}
                onClose={closeModal}
                email={selectedEmail}
            />
        </AuthenticatedLayout>
    );
}
