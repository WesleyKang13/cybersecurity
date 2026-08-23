<?php

declare(strict_types=1);

namespace App\Rules;

use App\Support\ThreatMetadata;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use JsonException;

class SafeThreatMetadata implements ValidationRule
{
    public const MAX_BYTES = ThreatMetadata::MAX_BYTES;

    public const MAX_DEPTH = ThreatMetadata::MAX_DEPTH;

    public const MAX_VALUES = ThreatMetadata::MAX_VALUES;

    /**
     * @param  Closure(string, ?string=): \Illuminate\Translation\PotentiallyTranslatedString  $fail
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_array($value)) {
            $fail('The :attribute field must be a structured object or array.');

            return;
        }

        try {
            $encoded = json_encode($value, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $fail('The :attribute field must contain valid JSON-compatible values.');

            return;
        }

        if (strlen($encoded) > self::MAX_BYTES) {
            $fail('The :attribute field must not exceed 16 KB when JSON encoded.');

            return;
        }

        $valueCount = 0;

        if (! $this->validateEntries($value, 1, $valueCount, $fail)) {
            return;
        }
    }

    /**
     * @param  array<array-key, mixed>  $entries
     * @param  Closure(string, ?string=): \Illuminate\Translation\PotentiallyTranslatedString  $fail
     */
    private function validateEntries(array $entries, int $depth, int &$valueCount, Closure $fail): bool
    {
        if ($depth > self::MAX_DEPTH) {
            $fail('The :attribute field must not exceed 6 levels of nesting.');

            return false;
        }

        foreach ($entries as $key => $value) {
            $valueCount++;

            if ($valueCount > self::MAX_VALUES) {
                $fail('The :attribute field must not contain more than 100 values.');

                return false;
            }

            if (is_string($key) && ThreatMetadata::isProhibitedKey($key)) {
                $fail("The :attribute field contains a prohibited sensitive key: {$key}.");

                return false;
            }

            if (is_array($value) && ! $this->validateEntries($value, $depth + 1, $valueCount, $fail)) {
                return false;
            }
        }

        return true;
    }
}
