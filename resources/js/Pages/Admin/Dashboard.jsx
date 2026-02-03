import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head } from '@inertiajs/react';
import { useState } from 'react';
import ThreatDetailModal from '@/Pages/Partials/ThreatDetailModal';
import { ShieldAlert } from 'lucide-react';

export default function AdminDashboard({ auth, threats }) {
    const [selectedThreat, setSelectedThreat] = useState(null);
    const [showModal, setShowModal] = useState(false);

    const openModal = (threat) => {
        setSelectedThreat(threat);
        setShowModal(true);
    };

    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">Organization Threat Overview</h2>}
        >
            <Head title="Admin Dashboard" />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8">

                    {/* Admin Summary Card */}
                    <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg mb-6 p-6 border-l-4 border-red-500">
                        <h3 className="text-lg font-bold text-gray-900">High Priority Alerts</h3>
                        <p className="text-gray-600">
                            Found {threats.length} high-severity threats across your organization.
                        </p>
                    </div>

                    {/* Threat Table */}
                    <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                        <div className="p-6 text-gray-900">
                            {threats.length === 0 ? (
                                <p className="text-center text-gray-500 py-10">No high threats detected. Good job!</p>
                            ) : (
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Employee</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subject</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {threats.map((threat) => (
                                            <tr key={threat.id} className="hover:bg-red-50 transition-colors">
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                        <ShieldAlert className="w-4 h-4 mr-1" />
                                                        HIGH
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-bold">
                                                    {threat.user.name} {/* From eager loading */}
                                                </td>
                                                <td className="px-6 py-4 text-sm text-gray-500 truncate max-w-xs">
                                                    {threat.subject}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    {new Date(threat.created_at).toLocaleDateString()}
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                    <button
                                                        onClick={() => openModal(threat)}
                                                        className="text-indigo-600 hover:text-indigo-900 font-semibold"
                                                    >
                                                        Review
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Reusing the Modal Logic */}
            <ThreatDetailModal
                show={showModal}
                onClose={() => setShowModal(false)}
                email={selectedThreat}
            />
        </AuthenticatedLayout>
    );
}
