import InputError from '@/Components/InputError';
import InputLabel from '@/Components/InputLabel';
import PrimaryButton from '@/Components/PrimaryButton';
import SecondaryButton from '@/Components/SecondaryButton';
import TextInput from '@/Components/TextInput';
import AuthenticatedLayout from '@/Layouts/AuthenticatedLayout';
import { formatUserRole, USER_ROLES } from '@/constants/roles';
import { Head, Link, useForm, usePage } from '@inertiajs/react';
import { useEffect, useState } from 'react';

const sections = [
    { key: 'overview', label: 'Overview' },
    { key: 'users', label: 'Users' },
    { key: 'settings', label: 'Settings' },
];

function ClientUserRow({ companyId, user, clientRoles }) {
    const { data, setData, patch, processing, errors } = useForm({
        role: user.role,
    });
    const roleIsEditable = clientRoles.includes(user.role);

    const submit = (event) => {
        event.preventDefault();
        patch(route('platform.client-companies.users.update', [companyId, user.id]), {
            preserveScroll: true,
        });
    };

    if (!roleIsEditable) {
        return (
            <div className="grid gap-3 px-6 py-4 sm:grid-cols-[minmax(0,1fr)_12rem_auto] sm:items-center">
                <div className="min-w-0">
                    <p className="truncate font-medium text-gray-900">{user.name}</p>
                    <p className="truncate text-sm text-gray-500">{user.email}</p>
                </div>
                <p className="text-sm font-medium text-amber-700">{formatUserRole(user.role)}</p>
                <p className="text-xs text-gray-500">Requires data review</p>
            </div>
        );
    }

    return (
        <form onSubmit={submit} className="grid gap-3 px-6 py-4 sm:grid-cols-[minmax(0,1fr)_12rem_auto] sm:items-center">
            <div className="min-w-0">
                <p className="truncate font-medium text-gray-900">{user.name}</p>
                <p className="truncate text-sm text-gray-500">{user.email}</p>
            </div>
            <div>
                <select
                    aria-label={`Role for ${user.name}`}
                    value={data.role}
                    onChange={(event) => setData('role', event.target.value)}
                    className="block w-full rounded-md border-gray-300 text-sm shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                >
                    {clientRoles.map((role) => (
                        <option key={role} value={role}>{formatUserRole(role)}</option>
                    ))}
                </select>
                <InputError message={errors.role} className="mt-1" />
            </div>
            <PrimaryButton disabled={processing || data.role === user.role}>
                Update role
            </PrimaryButton>
        </form>
    );
}

export default function ClientCompanyShow({ company, eligibleUsers = [], clientRoles = [] }) {
    const { flash = {} } = usePage().props;
    const [activeSection, setActiveSection] = useState('users');
    const [showAddUser, setShowAddUser] = useState(false);
    const companyForm = useForm({
        name: company.name,
        domain: company.domain || '',
        status: company.status,
    });
    const accountForm = useForm({
        name: '',
        email: '',
        account_role: USER_ROLES.CLIENT_USER,
    });
    const assignmentForm = useForm({
        user_id: eligibleUsers[0]?.id || '',
        role: USER_ROLES.CLIENT_USER,
    });

    useEffect(() => {
        const selectedUserStillEligible = eligibleUsers.some(
            (user) => String(user.id) === String(assignmentForm.data.user_id),
        );

        if (!selectedUserStillEligible) {
            assignmentForm.setData('user_id', eligibleUsers[0]?.id || '');
        }
    }, [eligibleUsers, assignmentForm.data.user_id]);

    const createUser = (event) => {
        event.preventDefault();
        accountForm.post(route('platform.client-companies.user-accounts.store', company.id), {
            preserveScroll: true,
            onSuccess: () => {
                accountForm.reset();
                setShowAddUser(false);
            },
        });
    };

    const assignUser = (event) => {
        event.preventDefault();
        assignmentForm.post(route('platform.client-companies.users.store', company.id), {
            preserveScroll: true,
        });
    };

    const updateCompany = (event) => {
        event.preventDefault();
        companyForm.patch(route('platform.client-companies.update', company.id), {
            preserveScroll: true,
        });
    };

    return (
        <AuthenticatedLayout
            header={(
                <div>
                    <Link
                        href={route('platform.client-companies.index')}
                        className="text-sm font-medium text-indigo-600 hover:text-indigo-800"
                    >
                        ← Client Companies
                    </Link>
                    <div className="mt-2 flex flex-wrap items-end justify-between gap-4">
                        <div>
                            <h2 className="text-2xl font-semibold text-gray-900">{company.name}</h2>
                            <p className="mt-1 text-sm text-gray-500">
                                <span className={company.status === 'active' ? 'text-emerald-600' : 'text-gray-500'}>
                                    {company.status === 'active' ? 'Active' : 'Inactive'}
                                </span>
                                {' · Client Company'}
                                {company.domain ? ` · ${company.domain}` : ''}
                            </p>
                        </div>
                    </div>
                </div>
            )}
        >
            <Head title={company.name} />

            <div className="py-8">
                <div className="mx-auto max-w-7xl space-y-6 px-4 sm:px-6 lg:px-8">
                    {flash.success && (
                        <div className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
                            {flash.success}
                        </div>
                    )}

                    {flash.account_setup_url && (
                        <div className="rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-800">
                            <p className="font-semibold">Local account-setup link</p>
                            <p className="mt-1 text-xs text-indigo-700">
                                This link is shown only in local/testing environments and expires after 60 minutes.
                            </p>
                            <a
                                href={flash.account_setup_url}
                                className="mt-2 block break-all font-medium underline"
                            >
                                {flash.account_setup_url}
                            </a>
                        </div>
                    )}

                    <div className="border-b border-gray-200">
                        <nav className="-mb-px flex gap-6" aria-label="Client company sections">
                            {sections.map((section) => (
                                <button
                                    key={section.key}
                                    type="button"
                                    onClick={() => setActiveSection(section.key)}
                                    className={`border-b-2 px-1 py-3 text-sm font-semibold ${activeSection === section.key
                                        ? 'border-indigo-600 text-indigo-600'
                                        : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
                                    }`}
                                >
                                    {section.label}
                                </button>
                            ))}
                        </nav>
                    </div>

                    {activeSection === 'overview' && (
                        <section className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
                            <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-gray-200">
                                <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Company type</p>
                                <p className="mt-2 font-semibold text-gray-900">Client Company</p>
                            </div>
                            <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-gray-200">
                                <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Status</p>
                                <p className="mt-2 font-semibold capitalize text-gray-900">{company.status}</p>
                            </div>
                            <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-gray-200">
                                <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Domain</p>
                                <p className="mt-2 truncate font-semibold text-gray-900">{company.domain || 'Not set'}</p>
                            </div>
                            <div className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-gray-200">
                                <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Users</p>
                                <p className="mt-2 font-semibold text-gray-900">{company.users.length}</p>
                            </div>
                        </section>
                    )}

                    {activeSection === 'users' && (
                        <div className="space-y-6">
                            <section className="overflow-hidden rounded-xl bg-white shadow-sm ring-1 ring-gray-200">
                                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 px-6 py-5">
                                    <div>
                                        <h3 className="text-lg font-semibold text-gray-900">Users</h3>
                                        <p className="mt-1 text-sm text-gray-500">
                                            Client admins and users assigned specifically to {company.name}.
                                        </p>
                                    </div>
                                    <PrimaryButton type="button" onClick={() => setShowAddUser((open) => !open)}>
                                        + Add User
                                    </PrimaryButton>
                                </div>

                                {showAddUser && (
                                    <form onSubmit={createUser} className="border-b border-gray-200 bg-gray-50 p-6">
                                        <h4 className="font-semibold text-gray-900">Create client account</h4>
                                        <p className="mt-1 text-sm text-gray-500">
                                            New users receive a secure single-use account-setup link. Existing eligible emails are linked without duplication.
                                        </p>
                                        <div className="mt-5 grid gap-4 md:grid-cols-3">
                                            <div>
                                                <InputLabel htmlFor="account-name" value="Name" />
                                                <TextInput
                                                    id="account-name"
                                                    value={accountForm.data.name}
                                                    onChange={(event) => accountForm.setData('name', event.target.value)}
                                                    className="mt-1 block w-full"
                                                    required
                                                />
                                                <InputError message={accountForm.errors.name} className="mt-2" />
                                            </div>
                                            <div>
                                                <InputLabel htmlFor="account-email" value="Email" />
                                                <TextInput
                                                    id="account-email"
                                                    type="email"
                                                    value={accountForm.data.email}
                                                    onChange={(event) => accountForm.setData('email', event.target.value)}
                                                    className="mt-1 block w-full"
                                                    required
                                                />
                                                <InputError message={accountForm.errors.email} className="mt-2" />
                                            </div>
                                            <div>
                                                <InputLabel htmlFor="account-role" value="Role" />
                                                <select
                                                    id="account-role"
                                                    value={accountForm.data.account_role}
                                                    onChange={(event) => accountForm.setData('account_role', event.target.value)}
                                                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                                                >
                                                    {clientRoles.map((role) => (
                                                        <option key={role} value={role}>{formatUserRole(role)}</option>
                                                    ))}
                                                </select>
                                                <InputError message={accountForm.errors.account_role} className="mt-2" />
                                            </div>
                                        </div>
                                        <div className="mt-5 flex gap-3">
                                            <PrimaryButton disabled={accountForm.processing}>
                                                Create / Send Account Setup
                                            </PrimaryButton>
                                            <SecondaryButton onClick={() => setShowAddUser(false)}>Cancel</SecondaryButton>
                                        </div>
                                    </form>
                                )}

                                {company.users.length === 0 ? (
                                    <p className="px-6 py-10 text-center text-sm text-gray-500">No users are assigned to this company.</p>
                                ) : (
                                    <div className="divide-y divide-gray-100">
                                        {company.users.map((user) => (
                                            <ClientUserRow
                                                key={user.id}
                                                companyId={company.id}
                                                user={user}
                                                clientRoles={clientRoles}
                                            />
                                        ))}
                                    </div>
                                )}
                            </section>

                            <section className="rounded-xl bg-white p-6 shadow-sm ring-1 ring-gray-200">
                                <h3 className="text-lg font-semibold text-gray-900">Assign Existing Account</h3>
                                <p className="mt-1 text-sm text-gray-500">
                                    Secondary workflow for eligible transitional accounts that do not yet belong to a company.
                                </p>

                                {eligibleUsers.length === 0 ? (
                                    <p className="mt-5 rounded-lg bg-gray-50 px-4 py-4 text-sm text-gray-600">
                                        No eligible unassigned users are currently available.
                                    </p>
                                ) : (
                                    <form onSubmit={assignUser} className="mt-5 grid gap-4 md:grid-cols-[minmax(0,1fr)_14rem_auto] md:items-end">
                                        <div>
                                            <InputLabel htmlFor="existing-user" value="Unassigned user" />
                                            <select
                                                id="existing-user"
                                                value={assignmentForm.data.user_id}
                                                onChange={(event) => assignmentForm.setData('user_id', event.target.value)}
                                                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                                                required
                                            >
                                                {eligibleUsers.map((user) => (
                                                    <option key={user.id} value={user.id}>
                                                        {user.name} ({user.email}) · {formatUserRole(user.role)}
                                                    </option>
                                                ))}
                                            </select>
                                            <InputError message={assignmentForm.errors.user_id} className="mt-2" />
                                        </div>
                                        <div>
                                            <InputLabel htmlFor="existing-role" value="Client role" />
                                            <select
                                                id="existing-role"
                                                value={assignmentForm.data.role}
                                                onChange={(event) => assignmentForm.setData('role', event.target.value)}
                                                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                                            >
                                                {clientRoles.map((role) => (
                                                    <option key={role} value={role}>{formatUserRole(role)}</option>
                                                ))}
                                            </select>
                                            <InputError message={assignmentForm.errors.role} className="mt-2" />
                                        </div>
                                        <PrimaryButton disabled={assignmentForm.processing}>Assign account</PrimaryButton>
                                    </form>
                                )}
                            </section>
                        </div>
                    )}

                    {activeSection === 'settings' && (
                        <section className="max-w-2xl rounded-xl bg-white p-6 shadow-sm ring-1 ring-gray-200">
                            <h3 className="text-lg font-semibold text-gray-900">Company settings</h3>
                            <p className="mt-1 text-sm text-gray-500">
                                Tenant type is locked to client. Deactivation preserves all users and history.
                            </p>
                            <form onSubmit={updateCompany} className="mt-6 space-y-5">
                                <div>
                                    <InputLabel htmlFor="company-name" value="Company name" />
                                    <TextInput
                                        id="company-name"
                                        value={companyForm.data.name}
                                        onChange={(event) => companyForm.setData('name', event.target.value)}
                                        className="mt-1 block w-full"
                                        required
                                    />
                                    <InputError message={companyForm.errors.name} className="mt-2" />
                                </div>
                                <div>
                                    <InputLabel htmlFor="company-domain" value="Domain (optional)" />
                                    <TextInput
                                        id="company-domain"
                                        value={companyForm.data.domain}
                                        onChange={(event) => companyForm.setData('domain', event.target.value)}
                                        className="mt-1 block w-full"
                                    />
                                    <InputError message={companyForm.errors.domain} className="mt-2" />
                                </div>
                                <div>
                                    <InputLabel htmlFor="company-status" value="Status" />
                                    <select
                                        id="company-status"
                                        value={companyForm.data.status}
                                        onChange={(event) => companyForm.setData('status', event.target.value)}
                                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500"
                                    >
                                        <option value="active">Active</option>
                                        <option value="inactive">Inactive</option>
                                    </select>
                                    <InputError message={companyForm.errors.status} className="mt-2" />
                                </div>
                                <PrimaryButton disabled={companyForm.processing}>Save settings</PrimaryButton>
                            </form>
                        </section>
                    )}
                </div>
            </div>
        </AuthenticatedLayout>
    );
}
