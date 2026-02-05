import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, useForm } from '@inertiajs/react'; // Import useForm
import { useState } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';
import Modal from '@/Components/Modal'; // For Add User Form
import SecondaryButton from '@/Components/SecondaryButton';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import InputLabel from '@/Components/InputLabel';
import InputError from '@/Components/InputError';
import { ShieldAlert, Mail, MessageSquare, Users, LayoutDashboard, UserPlus } from 'lucide-react';

export default function AdminDashboard({ auth, threats, users }) {
    // State for View Switching
    const [activeTab, setActiveTab] = useState('threats'); // 'threats' or 'users'

    // State for Modals
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [showThreatModal, setShowThreatModal] = useState(false);
    const [showUserModal, setShowUserModal] = useState(false);

    // Form for Adding User
    const { data, setData, post, processing, reset, errors } = useForm({
        name: '',
        email: '',
    });

    const openThreatModal = (threat) => {
        setSelectedThreat(threat);
        setShowThreatModal(true);
    };

    const submitUser = (e) => {
        e.preventDefault();
        post(route('admin.users.store'), {
            onSuccess: () => {
                setShowUserModal(false);
                reset();
            },
        });
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Admin Console</h2>}
        >
            <Head title="Admin Dashboard" />

            {/* FULL WIDTH CONTAINER */}
            <div className="flex min-h-screen w-full bg-gray-100">

                {/* --- LEFT SIDEBAR (20%) --- */}
                <aside className="w-1/5 bg-white border-r border-gray-200 min-h-screen">
                    <div className="p-6">
                        <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-4">
                            Menu
                        </h3>
                        <nav className="space-y-2">
                            <button
                                onClick={() => setActiveTab('threats')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${
                                    activeTab === 'threats'
                                    ? 'bg-indigo-50 text-indigo-700'
                                    : 'text-gray-600 hover:bg-gray-50'
                                }`}
                            >
                                <LayoutDashboard className="w-5 h-5 mr-3" />
                                Threat Overview
                            </button>

                            <button
                                onClick={() => setActiveTab('users')}
                                className={`w-full flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${
                                    activeTab === 'users'
                                    ? 'bg-indigo-50 text-indigo-700'
                                    : 'text-gray-600 hover:bg-gray-50'
                                }`}
                            >
                                <Users className="w-5 h-5 mr-3" />
                                User Management
                            </button>
                        </nav>
                    </div>
                </aside>

                {/* --- RIGHT CONTENT (80%) --- */}
                <main className="w-4/5 p-8">

                    {/* VIEW 1: THREAT OVERVIEW */}
                    {activeTab === 'threats' && (
                        <div>
                            <div className="mb-6 flex justify-between items-center">
                                <h3 className="text-2xl font-bold text-gray-800">High Priority Alerts</h3>
                                <span className="bg-red-100 text-red-800 text-xs font-bold px-3 py-1 rounded-full">
                                    {threats.length} Active Threats
                                </span>
                            </div>

                            <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Employee</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject/Content</th>
                                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {threats.map((threat) => (
                                            <tr key={`${threat.type}-${threat.id}`} className="hover:bg-red-50 transition-colors">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <div className="flex items-center">
                                                        {threat.type === 'email' ? (
                                                            <Mail className="w-4 h-4 text-blue-500 mr-2" />
                                                        ) : (
                                                            <MessageSquare className="w-4 h-4 text-green-500 mr-2" />
                                                        )}
                                                        <span className="text-xs text-gray-400 uppercase font-bold">{threat.type}</span>
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                        <ShieldAlert className="w-4 h-4 mr-1" />
                                                        HIGH
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-bold">{threat.user?.name}</td>
                                                <td className="px-6 py-4 text-sm text-gray-500 truncate max-w-xs">
                                                    {threat.type === 'email' ? threat.subject : (threat.body || threat.snippet)}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                    <button onClick={() => openThreatModal(threat)} className="text-indigo-600 hover:text-indigo-900 font-semibold">Review</button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* VIEW 2: USER MANAGEMENT */}
                    {activeTab === 'users' && (
                        <div>
                            <div className="mb-6 flex justify-between items-center">
                                <h3 className="text-2xl font-bold text-gray-800">Organization Members</h3>
                                <PrimaryButton onClick={() => setShowUserModal(true)}>
                                    <UserPlus className="w-4 h-4 mr-2" />
                                    Add New User
                                </PrimaryButton>
                            </div>

                            <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Joined</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {users.map((user) => (
                                            <tr key={user.id} className="hover:bg-gray-50">
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.name}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.email}</td>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-green-100 text-green-800'}`}>
                                                        {user.role}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    {new Date(user.created_at).toLocaleDateString()}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                </main>
            </div>

            {/* MODAL 1: THREAT DETAILS */}
            <ThreatDetailModal
                show={showThreatModal}
                onClose={() => setShowThreatModal(false)}
                email={selectedThreat}
            />

            {/* MODAL 2: ADD USER */}
            <Modal show={showUserModal} onClose={() => setShowUserModal(false)} maxWidth="md">
                <div className="p-6">
                    <h2 className="text-lg font-medium text-gray-900">Add New User</h2>
                    <p className="mt-1 text-sm text-gray-600 mb-6">
                        Create a new account for your organization. Default password is "password".
                    </p>

                    <form onSubmit={submitUser}>
                        <div className="mb-4">
                            <InputLabel htmlFor="name" value="Full Name" />
                            <TextInput
                                id="name"
                                type="text"
                                className="mt-1 block w-full"
                                value={data.name}
                                onChange={(e) => setData('name', e.target.value)}
                                required
                            />
                            <InputError message={errors.name} className="mt-2" />
                        </div>

                        <div className="mb-6">
                            <InputLabel htmlFor="email" value="Email Address" />
                            <TextInput
                                id="email"
                                type="email"
                                className="mt-1 block w-full"
                                value={data.email}
                                onChange={(e) => setData('email', e.target.value)}
                                required
                            />
                            <InputError message={errors.email} className="mt-2" />
                        </div>

                        <div className="flex justify-end">
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

        </AuthenticatedLayout>
    );
}
