<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\GeminiAnalysisException;
use App\Support\GeminiResponseValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class GeminiResponseValidatorTest extends TestCase
{
    public static function invalidPayloads(): array
    {
        return [
            'empty response' => ['empty_response', 'invalid_response'],
            'missing field' => ['missing_risk', 'invalid_schema'],
            'numeric risk string' => ['numeric_risk', 'invalid_schema'],
            'negative risk' => ['negative_risk', 'invalid_schema'],
            'risk over 100' => ['high_risk', 'invalid_schema'],
            'invalid verdict' => ['invalid_verdict', 'invalid_schema'],
            'invalid category' => ['invalid_category', 'invalid_schema'],
            'empty chain' => ['empty_chain', 'invalid_schema'],
            'nested chain' => ['nested_chain', 'invalid_schema'],
            'empty reasoning' => ['empty_reasoning', 'invalid_schema'],
        ];
    }

    #[DataProvider('invalidPayloads')]
    public function test_invalid_email_contracts_are_rejected(string $case, string $code): void
    {
        $payload = $this->payload();
        $result = &$payload['candidates'][0]['content']['parts'][0]['text'];
        $decoded = json_decode($result, true);

        if ($case === 'empty_response') {
            $payload = [];
        } elseif ($case === 'missing_risk') {
            unset($decoded['risk_score']);
        } else {
            $field = match ($case) {
                'numeric_risk', 'negative_risk', 'high_risk' => 'risk_score',
                'invalid_verdict' => 'verdict',
                'invalid_category' => 'threat_category',
                'empty_chain', 'nested_chain' => 'analysis_chain',
                default => 'final_reasoning',
            };
            $decoded[$field] = match ($case) {
                'numeric_risk' => '1', 'negative_risk' => -1, 'high_risk' => 101,
                'invalid_verdict' => 'UNKNOWN', 'invalid_category' => 'Other',
                'empty_chain' => [], 'nested_chain' => [['nested']], default => '',
            };
        }
        if ($case !== 'empty_response') {
            $result = json_encode($decoded);
        }

        try {
            (new GeminiResponseValidator)->validateEmail($payload);
            $this->fail('Expected validation to fail.');
        } catch (GeminiAnalysisException $exception) {
            $this->assertSame($code, $exception->errorCode);
            $this->assertTrue($exception->retryable);
        }
    }

    public function test_safety_block_is_rejected_without_retrying(): void
    {
        $payload = $this->payload();
        $payload['candidates'][0]['finishReason'] = 'SAFETY';

        try {
            (new GeminiResponseValidator)->validateEmail($payload);
            $this->fail('Expected validation to fail.');
        } catch (GeminiAnalysisException $exception) {
            $this->assertSame('safety_blocked', $exception->errorCode);
            $this->assertFalse($exception->retryable);
        }
    }

    public function test_pdf_payment_indicator_must_be_a_boolean(): void
    {
        $payload = $this->payload(['is_payment_request' => 'false']);

        $this->expectException(GeminiAnalysisException::class);
        (new GeminiResponseValidator)->validateFinancialAttachment($payload);
    }

    private function payload(array $replace = []): array
    {
        $result = array_merge([
            'risk_score' => 10,
            'verdict' => 'SAFE',
            'threat_category' => 'None',
            'analysis_chain' => ['Sender reviewed.'],
            'final_reasoning' => 'A complete concise reason.',
            'is_payment_request' => false,
        ], $replace);

        return ['candidates' => [['content' => ['parts' => [['text' => json_encode($result)]]]]]];
    }
}
