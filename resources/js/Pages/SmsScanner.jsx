import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head } from '@inertiajs/react';

export default function SmsScanner({ auth }) {
    return (
        <AuthenticatedLayout
            user={auth.user}
            header={<h2 className="font-semibold text-xl text-gray-800 leading-tight">SMS & Text Scanner</h2>}
        >
            <Head title="SMS Scanner" />

            <div className="py-12">
                <div className="max-w-7xl mx-auto sm:px-6 lg:px-8">
                    <div className="bg-white overflow-hidden shadow-sm sm:rounded-lg p-6 text-center">
                        <h3 className="text-lg font-medium text-gray-900">
                            🚧 SMS Scanner Under Construction
                        </h3>
                        <p className="text-gray-500 mt-2">
                            Phase 3 of PhishGuard is starting now...
                        </p>
                    </div>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
