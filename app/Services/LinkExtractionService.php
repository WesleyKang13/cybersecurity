<?php

declare(strict_types=1);

namespace App\Services;

use DOMDocument;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

class LinkExtractionService
{
    private const RESOLUTION_CACHE_TTL = 86400;
    private const CONNECT_TIMEOUT_SECONDS = 3;
    private const REQUEST_TIMEOUT_SECONDS = 5;
    private const MAX_REDIRECT_HOPS = 5;
    private const MAX_HTML_LENGTH = 250000;
    private const MAX_TEXT_LENGTH = 150000;

    private const SHORTENER_DOMAINS = [
        'bit.ly',
        'tinyurl.com',
        't.co',
        'ow.ly',
        'buff.ly',
        'rebrand.ly',
        'goo.gl',
        'lnkd.in',
        'is.gd',
        'cutt.ly',
        'rb.gy',
        'shorturl.at',
    ];

    public function extractAndInspect(string $htmlBody, string $textBody): array
    {
        $preparedHtml = $this->prepareContent($htmlBody, self::MAX_HTML_LENGTH);
        $preparedText = $this->prepareContent($textBody, self::MAX_TEXT_LENGTH);
        $links = [];

        foreach ($this->extractAnchorTags($preparedHtml) as $link) {
            $this->storeStructuredLink($links, $link['url'], $link['anchor_text']);
        }

        foreach ($this->extractUrlsFromText($preparedHtml) as $url) {
            $this->storeStructuredLink($links, $url, null);
        }

        foreach ($this->extractUrlsFromText($preparedText) as $url) {
            $this->storeStructuredLink($links, $url, null);
        }

        return array_values($links);
    }

    public function resolveRedirect(string $url): string
    {
        $normalizedUrl = $this->normalizeUrl($url);

        if ($normalizedUrl === null) {
            return $url;
        }

        $cacheKey = 'resolved_link_' . sha1($normalizedUrl);
        $cached = Cache::get($cacheKey);

        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        try {
            $resolvedUrl = $normalizedUrl;

            for ($hop = 0; $hop < self::MAX_REDIRECT_HOPS; $hop++) {
                $response = Http::connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                    ->timeout(self::REQUEST_TIMEOUT_SECONDS)
                    ->withOptions(['allow_redirects' => false])
                    ->head($resolvedUrl);

                if ($response->redirect()) {
                    $location = $response->header('Location');
                    $nextUrl = is_string($location) ? $this->normalizeUrl($location) : null;

                    if ($nextUrl === null || $nextUrl === $resolvedUrl) {
                        break;
                    }

                    $resolvedUrl = $nextUrl;
                    continue;
                }

                if ($response->successful() || $response->status() < 400) {
                    Cache::put($cacheKey, $resolvedUrl, self::RESOLUTION_CACHE_TTL);

                    return $resolvedUrl;
                }

                break;
            }

            return $normalizedUrl;
        } catch (Throwable) {
            return $normalizedUrl;
        }
    }

    /**
     * @return array<int, array{url: string, anchor_text: string}>
     */
    private function extractAnchorTags(string $htmlBody): array
    {
        if (trim($htmlBody) === '') {
            return [];
        }

        try {
            $previousUseInternalErrors = libxml_use_internal_errors(true);
            $document = new DOMDocument();
            $loaded = $document->loadHTML('<?xml encoding="utf-8" ?>' . $htmlBody, LIBXML_NOERROR | LIBXML_NOWARNING);
            libxml_clear_errors();
            libxml_use_internal_errors($previousUseInternalErrors);

            if (!$loaded) {
                return [];
            }
        } catch (Throwable) {
            return [];
        }

        $links = [];

        foreach ($document->getElementsByTagName('a') as $anchor) {
            $href = html_entity_decode(trim((string) $anchor->getAttribute('href')), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $url = $this->normalizeUrl($href);

            if ($url === null) {
                continue;
            }

            $links[] = [
                'url' => $url,
                'anchor_text' => trim(html_entity_decode((string) $anchor->textContent, ENT_QUOTES | ENT_HTML5, 'UTF-8')),
            ];
        }

        return $links;
    }

    /**
     * @return array<int, string>
     */
    private function extractUrlsFromText(string $text): array
    {
        if (trim($text) === '') {
            return [];
        }

        preg_match_all('~https?://[^\s<>"\']+~i', html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8'), $matches);

        return array_values(array_unique(array_map(function ($url) {
            return $this->trimTrailingPunctuation($url);
        }, $matches[0] ?? [])));
    }

    private function storeStructuredLink(array &$links, string $url, ?string $anchorText): void
    {
        $normalizedUrl = $this->normalizeUrl($url);

        if ($normalizedUrl === null) {
            return;
        }

        $domain = $this->extractDomain($normalizedUrl);
        $resolvedUrl = $domain !== null && $this->shouldResolveRedirect($domain)
            ? $this->resolveRedirect($normalizedUrl)
            : $normalizedUrl;
        $resolvedDomain = $this->extractDomain($resolvedUrl);
        $visibleDomain = $this->extractDisplayDomain((string) $anchorText);
        $hasTextMismatch = $visibleDomain !== null
            && (
                ($domain !== null && $visibleDomain !== $domain)
                || ($resolvedDomain !== null && $visibleDomain !== $resolvedDomain)
            );

        $linkKey = sha1($normalizedUrl);
        $normalizedAnchorText = $anchorText !== null && trim($anchorText) !== '' ? trim($anchorText) : null;

        if (isset($links[$linkKey])) {
            if ($links[$linkKey]['anchor_text'] === null && $normalizedAnchorText !== null) {
                $links[$linkKey]['anchor_text'] = $normalizedAnchorText;
            }

            $links[$linkKey]['resolved_url'] = $links[$linkKey]['resolved_url'] ?? $resolvedUrl;
            $links[$linkKey]['resolved_domain'] = $links[$linkKey]['resolved_domain'] ?? $resolvedDomain;
            $links[$linkKey]['has_text_mismatch'] = $links[$linkKey]['has_text_mismatch'] || $hasTextMismatch;
            $links[$linkKey]['has_suspicious_mismatch'] = $links[$linkKey]['has_suspicious_mismatch'] || $hasTextMismatch;

            return;
        }

        $links[$linkKey] = [
            'url' => $normalizedUrl,
            'anchor_text' => $normalizedAnchorText,
            'domain' => $domain,
            'resolved_url' => $resolvedUrl,
            'resolved_domain' => $resolvedDomain,
            'has_text_mismatch' => $hasTextMismatch,
            'has_suspicious_mismatch' => $hasTextMismatch,
        ];
    }

    private function normalizeUrl(string $url): ?string
    {
        $trimmed = $this->trimTrailingPunctuation(html_entity_decode(trim($url), ENT_QUOTES | ENT_HTML5, 'UTF-8'));

        if ($trimmed === '' || !preg_match('#^https?://#i', $trimmed)) {
            return null;
        }

        return filter_var($trimmed, FILTER_VALIDATE_URL) ? $trimmed : null;
    }

    private function trimTrailingPunctuation(string $url): string
    {
        return rtrim($url, " \t\n\r\0\x0B.,;:!?)]}>'\"");
    }

    private function extractDomain(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        if (!is_string($host) || trim($host) === '') {
            return null;
        }

        return $this->normalizeDomain($host);
    }

    private function extractDisplayDomain(string $text): ?string
    {
        $normalizedText = trim($text);

        if ($normalizedText === '') {
            return null;
        }

        if (!preg_match('/\b((?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b/i', $normalizedText, $matches)) {
            return null;
        }

        $candidate = $matches[1];
        $candidateUrl = preg_match('#^https?://#i', $candidate) ? $candidate : 'https://' . $candidate;

        return $this->extractDomain($candidateUrl);
    }

    private function normalizeDomain(string $domain): string
    {
        return strtolower(preg_replace('/^www\./i', '', trim($domain, '. ')) ?? $domain);
    }

    private function shouldResolveRedirect(string $domain): bool
    {
        return in_array($domain, self::SHORTENER_DOMAINS, true);
    }

    private function prepareContent(string $content, int $maxLength): string
    {
        $normalized = str_replace("\0", '', $content);

        return mb_substr($normalized, 0, $maxLength);
    }
}
