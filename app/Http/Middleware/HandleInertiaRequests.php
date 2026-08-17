<?php

namespace App\Http\Middleware;

use App\Support\PortalContext;
use Illuminate\Http\Request;
use Inertia\Middleware;

class HandleInertiaRequests extends Middleware
{
    /**
     * The root template that is loaded on the first page visit.
     *
     * @var string
     */
    protected $rootView = 'app';

    /**
     * Determine the current asset version.
     */
    public function version(Request $request): ?string
    {
        return parent::version($request);
    }

    /**
     * Define the props that are shared by default.
     *
     * @return array<string, mixed>
     */
    public function share(Request $request): array
    {
        $user = $request->user();

        return [
            ...parent::share($request),
            'auth' => [
                'user' => $user,
                'portal' => fn (): array => PortalContext::for($user),
                'can_access_platform' => fn (): bool => $user?->hasPlatformAccess() ?? false,
                'is_platform_owner' => fn (): bool => $user?->hasPlatformOwnerAccess() ?? false,
            ],
            'flash' => [
                'success' => fn () => $request->session()->get('success'),
                'error' => fn () => $request->session()->get('error'),
                'account_setup_url' => fn (): ?string => app()->environment(['local', 'testing'])
                    ? $request->session()->get('account_setup_url')
                    : null,
            ],
        ];
    }
}
