<?php

declare(strict_types=1);

namespace App\Support;

use RuntimeException;

final class GeminiAnalysisException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        public readonly bool $retryable,
        string $message = 'Gemini analysis did not complete.'
    ) {
        parent::__construct($message);
    }
}
