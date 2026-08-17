import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head } from '@inertiajs/react';
import DomainManager from './DomainManager';

export default function Whitelist({ domains = [] }) {
    return (
        <AuthenticatedLayout
            header={(
                <h2 className="text-xl font-semibold leading-tight text-gray-800">
                    Global Whitelist
                </h2>
            )}
        >
            <Head title="Global Whitelist" />

            <div className="py-10">
                <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                    <DomainManager domains={domains} />
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
