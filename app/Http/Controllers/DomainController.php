<?php

namespace App\Http\Controllers;

use App\Models\WhitelistedDomain;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class DomainController extends Controller
{

    public function index(){
        $domains = WhitelistedDomain::orderBy('created_at', 'desc')->get();

        return inertia('Admin/DomainManager', [
            'domains' => $domains
        ]);
    }

    /**
     * Store a newly created domain in storage.
     */
    public function store(Request $request)
    {
        $request->validate([
            'domain' => 'required|string|max:255|unique:whitelisted_domains,domain',
            'description' => 'nullable|string|max:255',
        ]);

        // Clean up the input (Strips "https://", "www.", and trailing slashes)
        $domain = strtolower(trim($request->domain));
        $domain = parse_url($domain, PHP_URL_HOST) ?? $domain; // Extracts host if it's a full URL
        $domain = preg_replace('/^www\./', '', $domain); // Removes www.

        WhitelistedDomain::create([
            'domain' => $domain,
            'description' => $request->description,
            'is_active' => true,
        ]);

        // 💥 THE MAGIC: Bust the cache so the Queue Worker updates instantly!
        Cache::forget('trusted_domains');

        return back()->with('success', "'{$domain}' added to whitelist successfully.");
    }

    /**
     * Toggle the active status (The Kill-Switch).
     */
    public function update(Request $request, WhitelistedDomain $domain)
    {
        $request->validate([
            'is_active' => 'required|boolean',
        ]);

        $domain->update([
            'is_active' => $request->is_active,
        ]);

        // 💥 Bust the cache
        Cache::forget('trusted_domains');

        $status = $domain->is_active ? 'Activated' : 'Deactivated';
        return back()->with('success', "Domain '{$domain->domain}' is now {$status}.");
    }

    /**
     * Remove the specified domain from storage.
     */
    public function destroy(WhitelistedDomain $domain)
    {
        $domainName = $domain->domain;

        $domain->delete();

        // 💥 Bust the cache
        Cache::forget('trusted_domains');

        return back()->with('success', "'{$domainName}' removed from whitelist.");
    }
}
