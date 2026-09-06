<?php

declare(strict_types=1);

namespace App\Support;

use App\Models\ScannedUrl;

/**
 * A bounded description of the first-URL reputation lookup. A missing result
 * is deliberately not represented as a clean result: callers must decide how
 * to handle unavailable reputation data.
 */
final readonly class VirusTotalScanResult
{
    public function __construct(
        public string $status,
        public ?ScannedUrl $record = null,
        public ?string $scannedUrl = null,
    ) {}

    public static function skippedNoUrl(): self
    {
        return new self('skipped_no_url');
    }

    public static function cached(ScannedUrl $record): self
    {
        return new self(
            (int) $record->malicious_votes > 0 ? 'cache_hit_flagged' : 'cache_hit_clean',
            $record,
            $record->url
        );
    }

    public static function apiChecked(ScannedUrl $record): self
    {
        return new self(
            (int) $record->malicious_votes > 0 ? 'api_checked_flagged' : 'api_checked_clean',
            $record,
            $record->url
        );
    }

    public static function forStatus(string $status, string $scannedUrl): self
    {
        return new self($status, null, $scannedUrl);
    }

    public function vendorFlagCount(): int
    {
        return (int) ($this->record?->malicious_votes ?? 0);
    }

    /** @return array<int, string> */
    public function vendorFlags(): array
    {
        return array_values($this->record?->vendor_flags ?? []);
    }
}
