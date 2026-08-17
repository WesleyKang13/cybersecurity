import InputError from '@/Components/InputError';
import InputLabel from '@/Components/InputLabel';
import PrimaryButton from '@/Components/PrimaryButton';
import TextInput from '@/Components/TextInput';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { Head, Link, useForm, usePage } from '@inertiajs/react';

const statusClasses = {
    active: 'bg-emerald-100 text-emerald-700',
    inactive: 'bg-gray-200 text-gray-700',
};

export default function ClientCompaniesIndex({ companies = [] }) {
    const { flash = {} } = usePage().props;
    const { data, setData, post, processing, errors, reset } = useForm({
        name: '',
        domain: '',
        status: 'active',
    });

    const submit = (event) => {
        event.preventDefault();
        post(route('platform.client-companies.store'), {
            preserveScroll: true,
            onSuccess: () => reset(),
        });
    };

    return (
        <AuthenticatedLayout
            header={(
                <div>
                    <p className="text-sm font-medium text-indigo-600">Management</p>
                    <h2 className="text-xl font-semibold leading-tight text-gray-800">
                        Client Companies
                    </h2>
                </div>
            )}
        >
            <Head title="Client Companies" />

            <div className="py-10">
                <div className="mx-auto grid max-w-7xl gap-8 px-4 sm:px-6 lg:grid-cols-[minmax(0,1fr)_22rem] lg:px-8">
                    <section className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-gray-200">
                        <div className="border-b border-gray-200 px-6 py-5">
                            <h3 className="text-lg font-semibold text-gray-900">Client directory</h3>
                            <p className="mt-1 text-sm text-gray-500">
                                Open a company to review its users or assign an existing account.
                            </p>
                        </div>

                        {flash.success && (
                            <div className="mx-6 mt-5 rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
                                {flash.success}
                            </div>
                        )}

                        {companies.length === 0 ? (
                            <div className="px-6 py-12 text-center">
                                <p className="font-medium text-gray-900">No client companies yet</p>
                                <p className="mt-1 text-sm text-gray-500">
                                    Create the first client company using the form on this page.
                                </p>
                            </div>
                        ) : (
                            <div className="divide-y divide-gray-100">
                                {companies.map((company) => (
                                    <Link
                                        key={company.id}
                                        href={route('platform.client-companies.show', company.id)}
                                        className="flex items-center justify-between gap-4 px-6 py-5 transition hover:bg-gray-50"
                                    >
                                        <div className="min-w-0">
                                            <p className="truncate font-semibold text-gray-900">{company.name}</p>
                                            <p className="mt-1 truncate text-sm text-gray-500">
                                                {company.domain || 'No company domain'} · {company.users_count} {company.users_count === 1 ? 'user' : 'users'}
                                            </p>
                                        </div>
                                        <div className="flex shrink-0 items-center gap-3">
                                            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${statusClasses[company.status] || statusClasses.inactive}`}>
                                                {company.status}
                                            </span>
                                            <span aria-hidden="true" className="text-gray-400">→</span>
                                        </div>
                                    </Link>
                                ))}
                            </div>
                        )}
                    </section>

                    <aside className="h-fit rounded-xl bg-white p-6 shadow-sm ring-1 ring-gray-200">
                        <h3 className="text-lg font-semibold text-gray-900">Create client company</h3>
                        <p className="mt-1 text-sm text-gray-500">
                            This workflow always creates a client tenant. It never creates a platform company.
                        </p>

                        <form onSubmit={submit} className="mt-6 space-y-5">
                            <div>
                                <InputLabel htmlFor="name" value="Company name" />
                                <TextInput
                                    id="name"
                                    value={data.name}
                                    onChange={(event) => setData('name', event.target.value)}
                                    className="mt-1 block w-full"
                                    required
                                />
                                <InputError message={errors.name} className="mt-2" />
                            </div>

                            <div>
                                <InputLabel htmlFor="domain" value="Domain (optional)" />
                                <TextInput
                                    id="domain"
                                    value={data.domain}
                                    onChange={(event) => setData('domain', event.target.value)}
                                    placeholder="example.com"
                                    className="mt-1 block w-full"
                                />
                                <InputError message={errors.domain} className="mt-2" />
                            </div>

                            <div>
                                <InputLabel htmlFor="status" value="Status" />
                                <select
                                    id="status"
                                    value={data.status}
                                    onChange={(event) => setData('status', event.target.value)}
                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                                >
                                    <option value="active">Active</option>
                                    <option value="inactive">Inactive</option>
                                </select>
                                <InputError message={errors.status} className="mt-2" />
                            </div>

                            <PrimaryButton disabled={processing}>Create company</PrimaryButton>
                        </form>
                    </aside>
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
