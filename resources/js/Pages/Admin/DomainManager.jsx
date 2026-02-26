import { useForm, router, usePage } from '@inertiajs/react';
import { ShieldCheck, Plus, Trash2, Power, PowerOff, CheckCircle } from 'lucide-react';
import { useState } from 'react';
import Modal from '@/Components/Modal';
import SecondaryButton from '@/Components/SecondaryButton';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import InputLabel from '@/Components/InputLabel';
import InputError from '@/Components/InputError';

export default function DomainManager({ domains = [] }) {
    const { flash } = usePage().props;
    const [showModal, setShowModal] = useState(false);

    const { data, setData, post, processing, errors, reset } = useForm({
        domain: '',
        description: '',
    });

    const submitDomain = (e) => {
        e.preventDefault();
        post(route('domains.store'), {
            onSuccess: () => closeModal(),
            preserveScroll: true,
        });
    };

    const closeModal = () => {
        setShowModal(false);
        reset();
    };

    const toggleStatus = (domain) => {
        router.patch(route('domains.update', domain.id), {
            is_active: !domain.is_active
        }, { preserveScroll: true });
    };

    const deleteDomain = (id) => {
        if (confirm("Are you sure you want to permanently delete this domain from the whitelist?")) {
            router.delete(route('domains.destroy', id), { preserveScroll: true });
        }
    };

    return (
        <div className="space-y-6">
            {/* Header Area */}
            <div className="flex justify-between items-center border-b border-gray-200 pb-4">
                <div>
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 flex items-center">
                        <ShieldCheck className="w-6 h-6 mr-2 text-green-500" />
                        Whitelist Manager
                    </h2>
                    <p className="mt-1 text-sm text-gray-500">Manage Layer 1 trusted domains to bypass AI scanning and save API quota.</p>
                </div>
                <button
                    onClick={() => setShowModal(true)}
                    className="inline-flex items-center px-4 py-2 bg-indigo-600 border border-transparent rounded-md font-semibold text-xs text-white uppercase tracking-widest hover:bg-indigo-500 transition shadow-sm"
                >
                    <Plus className="w-4 h-4 mr-1" /> Add Domain
                </button>
            </div>

            {/* Flash Success Message */}
            {flash?.success && (
                <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded flex items-center shadow-sm">
                    <CheckCircle className="w-5 h-5 mr-2" />
                    <span>{flash.success}</span>
                </div>
            )}

            {/* Main Table Card */}
            <div className="bg-white dark:bg-gray-800 overflow-hidden shadow-sm sm:rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead className="bg-gray-50 dark:bg-gray-700">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                            {domains.length > 0 ? (
                                domains.map((domain) => (
                                    <tr key={domain.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition duration-150">
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className="font-mono text-sm font-semibold text-gray-800 dark:text-gray-200">{domain.domain}</span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            {domain.description || <span className="italic opacity-50">No description</span>}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <button
                                                onClick={() => toggleStatus(domain)}
                                                className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold transition-colors ${
                                                    domain.is_active ? 'bg-green-100 text-green-800 hover:bg-red-100 hover:text-red-800' : 'bg-red-100 text-red-800 hover:bg-green-100 hover:text-green-800'
                                                }`}
                                            >
                                                {domain.is_active ? <Power className="w-3 h-3 mr-1" /> : <PowerOff className="w-3 h-3 mr-1" />}
                                                {domain.is_active ? 'ACTIVE' : 'DISABLED'}
                                            </button>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                            <button
                                                onClick={() => deleteDomain(domain.id)}
                                                className="text-gray-400 hover:text-red-600 transition"
                                            >
                                                <Trash2 className="w-5 h-5" />
                                            </button>
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="4" className="px-6 py-8 text-center text-gray-500">
                                        No trusted domains found. Add one to get started!
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Modal */}
            <Modal show={showModal} onClose={closeModal} maxWidth="md">
                <form onSubmit={submitDomain} className="p-6 bg-white dark:bg-gray-800">
                    <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100 mb-4">Add Trusted Domain</h2>

                    <div className="space-y-4">
                        <div>
                            <InputLabel htmlFor="domain" value="Domain Name" />
                            <TextInput
                                id="domain"
                                type="text"
                                className="mt-1 block w-full font-mono text-sm"
                                value={data.domain}
                                onChange={(e) => setData('domain', e.target.value)}
                                placeholder="e.g., github.com"
                                required
                            />
                            <InputError message={errors.domain} className="mt-2" />
                            <p className="text-xs text-gray-500 mt-1">Do not include https:// or www.</p>
                        </div>

                        <div>
                            <InputLabel htmlFor="description" value="Description (Optional)" />
                            <TextInput
                                id="description"
                                type="text"
                                className="mt-1 block w-full text-sm"
                                value={data.description}
                                onChange={(e) => setData('description', e.target.value)}
                                placeholder="e.g., Company internal communications"
                            />
                            <InputError message={errors.description} className="mt-2" />
                        </div>
                    </div>

                    <div className="mt-6 flex justify-end space-x-3">
                        <SecondaryButton onClick={closeModal}>Cancel</SecondaryButton>
                        <PrimaryButton disabled={processing}>Add to Whitelist</PrimaryButton>
                    </div>
                </form>
            </Modal>
        </div>
    );
}
