import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, usePage } from '@inertiajs/react';
import { ShieldAlert, ShieldCheck, Activity, Plus, CheckCircle, XCircle } from 'lucide-react';
import { useState } from 'react'; // Add useState
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal'; // Import our new component

export default function Dashboard({ auth, initialStats, isConnected, recentAlerts }) {
    const { flash } = usePage().props;

    // Use real data passed from Laravel
    const statsData = initialStats || { scanned: 0, threats: 0, protected: 0 };

    const stats = [
        { name: 'Emails Scanned', value: statsData.scanned.toLocaleString(), icon: Activity, color: 'text-blue-500' },
        { name: 'Threats Detected', value: statsData.threats, icon: ShieldAlert, color: 'text-red-500' },
        { name: 'Protected Users', value: statsData.protected, icon: ShieldCheck, color: 'text-green-500' },
    ];

    const [selectedEmail, setSelectedEmail] = useState(null);
    const [showModal, setShowModal] = useState(false);

    const handleRowClick = (email) => {
        setSelectedEmail(email);
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setTimeout(() => setSelectedEmail(null), 300); // Clear data after animation
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 dark:text-gray-200 leading-tight">Security Command Center</h2>}
        >
            <Head title="Dashboard" />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-6">

                    {/* Flash Messages */}
                    {flash.success && (
                        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative flex items-center" role="alert">
                            <CheckCircle className="w-5 h-5 mr-2" />
                            <span className="block sm:inline">{flash.success}</span>
                        </div>
                    )}
                    {flash.error && (
                        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative flex items-center" role="alert">
                            <XCircle className="w-5 h-5 mr-2" />
                            <span className="block sm:inline">{flash.error}</span>
                        </div>
                    )}

                    {/* Main Action Section */}
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6 border-l-4 border-indigo-500">
                        <div className="flex items-center justify-between">
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

                            {/* Hide button if connected */}
                            {!isConnected && (
                                <a href={route('google.connect')} className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-500 focus:bg-indigo-700 transition ease-in-out duration-150">
                                    <Plus className="w-4 h-4 mr-2" />
                                    Connect Google
                                </a>
                            )}

                            {/* Show badge if connected */}
                            {isConnected && (
                                <span className="inline-flex items-center px-4 py-2 bg-green-100 text-green-800 border border-green-200 rounded-md font-semibold text-xs uppercase tracking-widest">
                                    <CheckCircle className="w-4 h-4 mr-2" />
                                    Connected
                                </span>
                            )}
                        </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
                        {stats.map((item) => (
                            <div key={item.name} className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg p-6">
                                <div className="flex items-center">
                                    <div className="flex-shrink-0">
                                        <item.icon className={`h-8 w-8 ${item.color}`} aria-hidden="true" />
                                    </div>
                                    <div className="ml-5 w-0 flex-1">
                                        <dl>
                                            <dt className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
                                                {item.name}
                                            </dt>
                                            <dd>
                                                <div className="text-lg font-medium text-gray-900 dark:text-gray-100">
                                                    {item.value}
                                                </div>
                                            </dd>
                                        </dl>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Recent Alerts Table (RESTORED) */}
                    <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg">
                        <div className="p-6 text-gray-900 dark:text-gray-100">
                            <h3 className="text-lg font-medium mb-4">Recent Security Alerts</h3>
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
                                                            {/* The Badge */}
                                                            <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                                                                alert.severity === 'high' ? 'bg-red-100 text-red-800' :
                                                                alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                                                                'bg-green-100 text-green-800'
                                                            }`}>
                                                                {alert.severity.toUpperCase()}
                                                            </span>

                                                            {/* The Risk Score (Only show if risky) */}
                                                            {alert.risk_score > 0 && (
                                                                <div className="flex items-center">
                                                                    <div className="w-16 bg-gray-200 rounded-full h-1.5 dark:bg-gray-700 mr-2">
                                                                        <div className={`h-1.5 rounded-full ${
                                                                            alert.risk_score > 75 ? 'bg-red-500' :
                                                                            alert.risk_score > 40 ? 'bg-yellow-500' : 'bg-green-500'
                                                                        }`} style={{ width: `${alert.risk_score}%` }}></div>
                                                                    </div>
                                                                    <span className="text-xs font-bold text-gray-500 dark:text-gray-400">
                                                                        {alert.risk_score}%
                                                                    </span>
                                                                </div>
                                                            )}
                                                        </div>
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                        {alert.subject}
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                        {alert.recipient}
                                                    </td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                                                        {alert.date}
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="4" className="px-6 py-4 text-center text-sm text-gray-500 dark:text-gray-400">
                                                    No scans performed yet.
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
