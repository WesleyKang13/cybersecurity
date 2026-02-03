import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage, Link, useForm } from '@inertiajs/react'; // Added Link and useForm
import { ShieldAlert, ShieldCheck, Activity, Plus, CheckCircle, XCircle, LogOut } from 'lucide-react';
import { useState } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';

export default function Dashboard({ auth, initialStats, isConnected, recentAlerts, filter }) { // Added filter prop
    const { flash } = usePage().props;
    const { post } = useForm(); // Hook for the Disconnect action

    // Stats Data
    const statsData = initialStats || { scanned: 0, threats: 0, protected: 0 };

    // Modal State
    const [selectedEmail, setSelectedEmail] = useState(null);
    const [showModal, setShowModal] = useState(false);

    const handleRowClick = (email) => {
        setSelectedEmail(email);
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setTimeout(() => setSelectedEmail(null), 300);
    };

    // Handle Disconnect
    const handleDisconnect = () => {
        if (confirm('Are you sure you want to disconnect? This will stop all security scanning.')) {
            post(route('google.disconnect'));
        }
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
        >
            <Head title="Dashboard" />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-6">

                    {/* Flash Messages */}
                    {flash.success && (
                        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative flex items-center">
                            <CheckCircle className="w-5 h-5 mr-2" />
                            <span>{flash.success}</span>
                        </div>
                    )}
                    {flash.error && (
                        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative flex items-center">
                            <XCircle className="w-5 h-5 mr-2" />
                            <span>{flash.error}</span>
                        </div>
                    )}

                    {/* 1. Connection & Action Section */}
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-l-4 border-indigo-500 flex justify-between items-center">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                                {isConnected ? 'Workspace Active' : 'No Workspace Connected'}
                            </h3>
                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                {isConnected
                                    ? 'System is currently scanning your connected account.'
                                    : 'Connect your Google Workspace to start scanning for phishing threats.'}
                            </p>
                        </div>

                        <div>
                            {!isConnected ? (
                                <a href={route('google.connect')} className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-500 transition">
                                    <Plus className="w-4 h-4 mr-2" />
                                    Connect Google
                                </a>
                            ) : (
                                // 🔴 UPDATED: Disconnect Button
                                <button
                                    onClick={handleDisconnect}
                                    className="inline-flex items-center px-4 py-2 bg-red-100 border border-transparent rounded-md font-semibold text-xs text-red-700 uppercase tracking-widest hover:bg-red-200 transition"
                                >
                                    <LogOut className="w-4 h-4 mr-2" />
                                    Disconnect
                                </button>
                            )}
                        </div>
                    </div>

                    {/* 2. Stats Grid - Only Show if Connected */}
                    {isConnected && (
                        <>
                            <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                                {/* Card 1: Scanned (Clickable Filter: All) */}
                                <Link
                                    href={route('dashboard', { filter: 'all' })}
                                    className={`bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 cursor-pointer border-2 transition duration-200 ${filter === 'all' || !filter ? 'border-blue-500' : 'border-transparent hover:border-gray-200'}`}
                                >
                                    <div className="flex items-center">
                                        <div className="flex-shrink-0">
                                            <Activity className="h-8 w-8 text-blue-500" />
                                        </div>
                                        <div className="ml-5">
                                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Emails Scanned</dt>
                                            <dd className="text-lg font-medium text-gray-900 dark:text-gray-100">{statsData.scanned.toLocaleString()}</dd>
                                        </div>
                                    </div>
                                </Link>

                                {/* Card 2: Threats (Clickable Filter: Threats) */}
                                <Link
                                    href={route('dashboard', { filter: 'threats' })}
                                    className={`bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 cursor-pointer border-2 transition duration-200 ${filter === 'threats' ? 'border-red-500' : 'border-transparent hover:border-gray-200'}`}
                                >
                                    <div className="flex items-center">
                                        <div className="flex-shrink-0">
                                            <ShieldAlert className="h-8 w-8 text-red-500" />
                                        </div>
                                        <div className="ml-5">
                                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Threats Detected</dt>
                                            <dd className="text-lg font-medium text-gray-900 dark:text-gray-100">{statsData.threats}</dd>
                                        </div>
                                    </div>
                                </Link>

                                {/* Card 3: Users (Static) */}
                                <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-2 border-transparent">
                                    <div className="flex items-center">
                                        <div className="flex-shrink-0">
                                            <ShieldCheck className="h-8 w-8 text-green-500" />
                                        </div>
                                        <div className="ml-5">
                                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400">Protected Users</dt>
                                            <dd className="text-lg font-medium text-gray-900 dark:text-gray-100">{statsData.protected}</dd>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* 3. Recent Alerts Table */}
                            <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg">
                                <div className="p-6 text-gray-900 dark:text-gray-100">
                                    <div className="flex justify-between items-center mb-4">
                                        <h3 className="text-lg font-medium">
                                            {filter === 'threats' ? '⚠️ Detected Threats' : 'Recent Activity'}
                                        </h3>
                                        {filter === 'threats' && (
                                            <Link href={route('dashboard')} className="text-sm text-blue-600 hover:underline">
                                                View All
                                            </Link>
                                        )}
                                    </div>

                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                            <thead className="bg-gray-50 dark:bg-gray-700">
                                                <tr>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Severity</th>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Subject</th>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Recipient</th>
                                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Date</th>
                                                </tr>
                                            </thead>
                                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                                {recentAlerts && recentAlerts.length > 0 ? (
                                                    recentAlerts.map((alert) => (
                                                        <tr
                                                            key={alert.id}
                                                            onClick={() => handleRowClick(alert)}
                                                            className="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors duration-150"
                                                        >
                                                            <td className="px-6 py-4 whitespace-nowrap">
                                                                <div className="flex items-center gap-3">
                                                                    <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                                        alert.severity === 'high' ? 'bg-red-100 text-red-800' :
                                                                        alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                                                        'bg-green-100 text-green-800'
                                                                    }`}>
                                                                        {alert.severity ? alert.severity.toUpperCase() : 'INFO'}
                                                                    </span>
                                                                    {alert.risk_score > 0 && (
                                                                        <span className="text-xs font-bold text-gray-500">
                                                                            {alert.risk_score}% Risk
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                                {alert.subject}
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                                {alert.recipient || 'Me'}
                                                            </td>
                                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                                {alert.date}
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="4" className="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">
                                                            {filter === 'threats' ? 'No threats detected!' : 'No scans performed yet.'}
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Modal remains unchanged */}
            <ThreatDetailModal
                show={showModal}
                onClose={closeModal}
                email={selectedEmail}
            />
        </AuthenticatedLayout>
    );
}
