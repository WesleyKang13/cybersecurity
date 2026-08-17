import Dropdown from '@/Components/Dropdown';
import NavLink from '@/Components/NavLink';
import ResponsiveNavLink from '@/Components/ResponsiveNavLink';
import { Link, usePage } from '@inertiajs/react';
import { useState } from 'react';

const navigationHref = (item) =>
    route(item.route, item.parameters || undefined);

const navigationIsActive = (item, currentUrl) => {
    const routeMatches = item.active_routes.some((routeName) => route().current(routeName));

    if (!routeMatches) {
        return false;
    }

    const currentTab = new URLSearchParams(currentUrl.split('?')[1] || '').get('tab');
    const requestedTab = item.parameters?.tab || null;

    if (requestedTab) {
        return route().current(item.route) ? currentTab === requestedTab : true;
    }

    if (item.key === 'security-overview') {
        return currentTab === null;
    }

    return true;
};

export default function AuthenticatedLayout({ header, children }) {
    const { props, url } = usePage();
    const { user, portal = {} } = props.auth;
    const navigation = portal.navigation || [];
    const sidebarNavigation = portal.sidebar_navigation || [];
    const isPlatform = portal.experience === 'platform';
    const mobileNavigation = isPlatform ? sidebarNavigation : navigation;
    const homeRoute = portal.landing_route || 'dashboard';
    const contextName = portal.company?.name || user.name;

    const [showingNavigationDropdown, setShowingNavigationDropdown] =
        useState(false);

    return (
        <div className="min-h-screen bg-gray-100">
            <nav className="border-b border-gray-200 bg-white shadow-sm">
                <div className="mx-auto max-w-full px-4 sm:px-6 lg:px-8">
                    <div className="flex h-16 justify-between">
                        <div className="flex min-w-0 items-center">
                            <Link href={route(homeRoute)} className="flex shrink-0 items-center">
                                <img
                                    src="/images/logo.png"
                                    alt="CyberSafe"
                                    className="block h-14 w-auto rounded-lg transition hover:scale-105"
                                />
                            </Link>

                            <div className="ml-3 hidden min-w-0 border-l border-gray-200 pl-3 md:block">
                                <p className="truncate text-sm font-semibold text-gray-900">
                                    {contextName}
                                </p>
                                <p className="truncate text-xs font-medium text-gray-500">
                                    {portal.title || 'Security Portal'}
                                </p>
                            </div>

                            {navigation.length > 0 && (
                                <div className="ml-6 hidden h-full items-center gap-4 xl:flex">
                                    {navigation.map((item) => (
                                        <NavLink
                                            key={item.key}
                                            href={navigationHref(item)}
                                            active={navigationIsActive(item, url)}
                                        >
                                            {item.label}
                                        </NavLink>
                                    ))}
                                </div>
                            )}
                        </div>

                        <div className={isPlatform ? 'hidden shrink-0 items-center lg:flex' : 'hidden shrink-0 items-center xl:flex'}>
                            <div className="relative ms-3">
                                <Dropdown>
                                    <Dropdown.Trigger>
                                        <span className="inline-flex rounded-md">
                                            <button
                                                type="button"
                                                className="inline-flex items-center rounded-md border border-transparent bg-white px-3 py-2 text-sm font-medium leading-4 text-gray-500 transition hover:text-gray-700 focus:outline-none"
                                            >
                                                {user.name}
                                                <svg
                                                    className="-me-0.5 ms-2 h-4 w-4"
                                                    xmlns="http://www.w3.org/2000/svg"
                                                    viewBox="0 0 20 20"
                                                    fill="currentColor"
                                                >
                                                    <path
                                                        fillRule="evenodd"
                                                        d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
                                                        clipRule="evenodd"
                                                    />
                                                </svg>
                                            </button>
                                        </span>
                                    </Dropdown.Trigger>

                                    <Dropdown.Content>
                                        <Dropdown.Link href={route('profile.edit')}>
                                            Profile
                                        </Dropdown.Link>
                                        <Dropdown.Link
                                            href={route('logout')}
                                            method="post"
                                            as="button"
                                        >
                                            Log Out
                                        </Dropdown.Link>
                                    </Dropdown.Content>
                                </Dropdown>
                            </div>
                        </div>

                        <div className={isPlatform ? '-me-2 flex items-center lg:hidden' : '-me-2 flex items-center xl:hidden'}>
                            <button
                                onClick={() => setShowingNavigationDropdown((open) => !open)}
                                className="inline-flex items-center justify-center rounded-md p-2 text-gray-400 transition hover:bg-gray-100 hover:text-gray-500 focus:bg-gray-100 focus:text-gray-500 focus:outline-none"
                                aria-label="Toggle navigation"
                            >
                                <svg className="h-6 w-6" stroke="currentColor" fill="none" viewBox="0 0 24 24">
                                    <path
                                        className={!showingNavigationDropdown ? 'inline-flex' : 'hidden'}
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        d="M4 6h16M4 12h16M4 18h16"
                                    />
                                    <path
                                        className={showingNavigationDropdown ? 'inline-flex' : 'hidden'}
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        d="M6 18L18 6M6 6l12 12"
                                    />
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>

                <div className={`${showingNavigationDropdown ? 'block' : 'hidden'} ${isPlatform ? 'lg:hidden' : 'xl:hidden'}`}>
                    <div className="border-t border-gray-100 px-3 pb-3 pt-3">
                        <div className="mb-3 rounded-lg bg-gray-50 px-3 py-2">
                            <p className="text-sm font-semibold text-gray-900">{contextName}</p>
                            <p className="text-xs font-medium text-gray-500">
                                {portal.title || 'Security Portal'}
                            </p>
                        </div>

                        {mobileNavigation.map((item, index) => (
                            <div key={item.key}>
                                {(index === 0 || mobileNavigation[index - 1].section !== item.section) && (
                                    <p className="px-3 pb-1 pt-3 text-xs font-semibold uppercase tracking-wider text-gray-400">
                                        {item.section}
                                    </p>
                                )}
                                <ResponsiveNavLink
                                    href={navigationHref(item)}
                                    active={navigationIsActive(item, url)}
                                >
                                    {item.label}
                                </ResponsiveNavLink>
                            </div>
                        ))}
                    </div>

                    <div className="border-t border-gray-200 pb-1 pt-4">
                        <div className="px-4">
                            <div className="text-base font-medium text-gray-800">{user.name}</div>
                            <div className="text-sm font-medium text-gray-500">{user.email}</div>
                        </div>

                        <div className="mt-3 space-y-1">
                            <ResponsiveNavLink
                                method="post"
                                href={route('logout')}
                                as="button"
                            >
                                Log Out
                            </ResponsiveNavLink>
                        </div>
                    </div>
                </div>
            </nav>

            <div className={isPlatform ? 'flex min-h-[calc(100vh-4rem)]' : ''}>
                {isPlatform && (
                    <aside className="hidden w-72 shrink-0 border-r border-gray-200 bg-white lg:block">
                        <nav className="sticky top-0 max-h-[calc(100vh-4rem)] space-y-1 overflow-y-auto p-5">
                            {sidebarNavigation.map((item, index) => (
                                <div key={item.key}>
                                    {(index === 0 || sidebarNavigation[index - 1].section !== item.section) && (
                                        <p className={`px-3 pb-2 text-xs font-semibold uppercase tracking-wider text-gray-400 ${index === 0 ? 'pt-0' : 'pt-5'}`}>
                                            {item.section}
                                        </p>
                                    )}
                                    <Link
                                        href={navigationHref(item)}
                                        className={`flex items-center rounded-md px-3 py-2 text-sm font-medium transition ${navigationIsActive(item, url)
                                            ? 'bg-indigo-50 text-indigo-700'
                                            : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                                        }`}
                                    >
                                        {item.label}
                                    </Link>
                                </div>
                            ))}
                        </nav>
                    </aside>
                )}

                <div className="min-w-0 flex-1">
                    {header && (
                        <header className="bg-white shadow">
                            <div className="mx-auto max-w-full px-4 py-6 sm:px-6 lg:px-8">
                                {header}
                            </div>
                        </header>
                    )}

                    <main>{children}</main>
                </div>
            </div>
        </div>
    );
}
