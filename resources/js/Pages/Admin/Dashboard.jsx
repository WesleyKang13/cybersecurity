import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, useForm, usePage } from '@inertiajs/react';
import { useState } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';
import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import InputLabel from '@/Components/InputLabel';
import InputError from '@/Components/InputError';
import {
    ShieldAlert, Mail, MessageSquare, Users, LayoutDashboard, UserPlus,
    FileText, Calendar, TrendingUp, CheckCircle, Smartphone
} from 'lucide-react';

export default function AdminDashboard({ auth, threats, users, reportData, filters }) {
    // 👇 Active Tab State
    const { props } = usePage(); // Get page props to check for errors

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

    // Form: Add User
    const { data, setData, post, processing, reset, errors } = useForm({
        name: '', email: '',
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

                            {/* 👇 NEW REPORTS TAB */}
                            <button
                                onClick={() => setActiveTab('reports')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${activeTab === 'reports' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-600 hover:bg-gray-50'}`}
                            >
                                <FileText className="w-5 h-5 mr-3" /> Reports & Analytics
                            </button>
                        </nav>
                    </div>
                </aside>

                {/* --- MAIN CONTENT --- */}
                <main className="w-4/5 p-8">

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
                                                        <p className="text-sm">Your organization is currently safe.</p>
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
                                    Organization Members
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
                                                        <button className="text-indigo-600 hover:text-indigo-900">Edit</button>
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan="5" className="px-6 py-10 text-center text-gray-500">
                                                    No users found in this organization.
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
                </main>
            </div>

            {/* Modals (Keep existing modals here) */}
             <ThreatDetailModal
                show={showThreatModal}
                onClose={() => setShowThreatModal(false)}
                email={selectedThreat}
            />

            <Modal show={showUserModal} onClose={() => setShowUserModal(false)} maxWidth="md">
                {/* ... existing user form ... */}
                 <div className="p-6">
                    <h2 className="text-lg font-medium text-gray-900">Add New User</h2>
                     <form onSubmit={submitUser}>
                         {/* ... inputs ... */}
                          <div className="flex justify-end mt-4">
                            <SecondaryButton onClick={() => setShowUserModal(false)} className="mr-3">Cancel</SecondaryButton>
                            <PrimaryButton disabled={processing}>Create User</PrimaryButton>
                        </div>
                     </form>
                 </div>
            </Modal>
        </AuthenticatedLayout>
    );
}
