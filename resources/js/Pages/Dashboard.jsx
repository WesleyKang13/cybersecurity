import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage, Link, useForm } from '@inertiajs/react';
import { ShieldAlert, ShieldCheck, Mail, Smartphone, Plus, CheckCircle, XCircle, LogOut } from 'lucide-react';
import { useState } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';

export default function Dashboard({ auth, initialStats, isConnected, recentAlerts, filter }) {
    const { flash } = usePage().props;
    const { post } = useForm();

    const statsData = initialStats || { emails_scanned: 0, sms_scanned: 0, threats: 0, protected: 1 };

    const [selectedEmail, setSelectedEmail] = useState(null);
    const [showModal, setShowModal] = useState(false);

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
        if (confirm('Are you sure you want to disconnect? Your emails will not be scan once disconnected')) {
            post(route('google.disconnect'));
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
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-l-4 border-indigo-500 flex justify-between items-center">
                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
                                {isConnected ? 'Workspace Active' : 'Limited Protection'}
                            </h3>
                            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                                {isConnected
                                    ? 'System is currently monitoring your Emails and SMS.'
                                    : 'Connect Google Workspace to enable Email scanning. SMS scanning is active.'}
                            </p>
                        </div>
                        <div>
                            {!isConnected ? (
                                <a href={route('google.connect')} className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-500 transition">
                                    <Plus className="w-4 h-4 mr-2" />
                                    Connect Google
                                </a>
                            ) : (
                                <button onClick={handleDisconnect} className="inline-flex items-center px-4 py-2 bg-red-100 border border-transparent rounded-md font-semibold text-xs text-red-700 uppercase tracking-widest hover:bg-red-200 transition">
                                    <LogOut className="w-4 h-4 mr-2" />
                                    Disconnect
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
                            <div className="flex justify-between items-center mb-4">
                                <h3 className="text-lg font-medium">Recent Activity Log</h3>
                                {filter !== 'all' && (
                                    <Link href={route('dashboard')} className="text-sm text-blue-600 hover:underline">
                                        Clear Filter
                                    </Link>
                                )}
                            </div>

                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                                    <thead className="bg-gray-50 dark:bg-gray-700">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                            {/* 🟢 NEW: Risk Column Header */}
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Score</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject / Content</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                        {recentAlerts && recentAlerts.length > 0 ? (
                                            recentAlerts.map((alert) => (
                                                <tr
                                                    key={alert.id}
                                                    onClick={() => handleRowClick(alert)}
                                                    className={`hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-150 ${alert.source === 'email' ? 'cursor-pointer' : ''}`}
                                                >
                                                    {/* Type Icon */}
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

                                                    {/* Status Badge */}
                                                    <td className="px-6 py-4 whitespace-nowrap">
                                                        <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                            alert.is_threat ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                                                        }`}>
                                                            {alert.is_threat ? 'THREAT' : 'SAFE'}
                                                        </span>
                                                    </td>

                                                    {/* 🟢 NEW: Risk Score Bar */}
                                                    <td className="px-6 py-4 whitespace-nowrap align-middle">
                                                        <div className="w-24">
                                                            <div className="flex justify-between text-xs mb-1">
                                                                <span className="font-bold text-gray-600 dark:text-gray-400">{alert.risk_score}%</span>
                                                            </div>
                                                            <div className="w-full bg-gray-200 rounded-full h-1.5 dark:bg-gray-700">
                                                                <div className={`h-1.5 rounded-full ${
                                                                    alert.risk_score > 75 ? 'bg-red-500' :
                                                                    alert.risk_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                                                                }`} style={{ width: `${alert.risk_score}%` }}></div>
                                                            </div>
                                                        </div>
                                                    </td>

                                                    {/* Subject / Content */}
                                                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-300 max-w-xs truncate">
                                                        <span className="block font-medium text-gray-900 dark:text-gray-100">{alert.subject}</span>
                                                        <span className="text-xs text-gray-400">{alert.sender}</span>
                                                    </td>

                                                    {/* Date */}
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                        {alert.date}
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="5" className="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">
                                                    No activity found.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
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
