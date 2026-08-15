export const USER_ROLES = Object.freeze({
    PLATFORM_OWNER: 'platform_owner',
    PLATFORM_STAFF: 'platform_staff',
    CLIENT_ADMIN: 'client_admin',
    CLIENT_USER: 'client_user',
});

export const isPlatformAdminRole = (role) =>
    role === USER_ROLES.PLATFORM_OWNER || role === USER_ROLES.PLATFORM_STAFF;

export const formatUserRole = (role) =>
    String(role || 'unclassified')
        .split('_')
        .filter(Boolean)
        .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
        .join(' ');
