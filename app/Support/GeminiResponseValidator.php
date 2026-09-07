<?php

declare(strict_types=1);

namespace App\Support;

final class GeminiResponseValidator
{
    private const VERDICTS = ['SAFE', 'SUSPICIOUS', 'MALICIOUS'];

    private const CATEGORIES = ['None', 'BEC/Invoice Fraud', 'Phishing', 'Malware', 'False Positive Noise'];

    private const MAX_CHAIN_ITEMS = 10;

    private const MAX_CHAIN_ITEM_LENGTH = 500;

    private const MAX_REASONING_LENGTH = 2000;

    /** @return array{risk_score: int, verdict: string, threat_category: string, analysis_chain: array<int, string>, final_reasoning: string} */
    public function validateEmail(array $payload): array
    {
        $decoded = $this->decodeCandidate($payload);
        $required = ['risk_score', 'verdict', 'threat_category', 'analysis_chain', 'final_reasoning'];

        foreach ($required as $field) {
            if (! array_key_exists($field, $decoded)) {
                throw new GeminiAnalysisException('invalid_schema', true, "Gemini response omitted {$field}.");
            }
        }

        if (! is_int($decoded['risk_score']) || $decoded['risk_score'] < 0 || $decoded['risk_score'] > 100) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini risk score was invalid.');
        }
        if (! is_string($decoded['verdict']) || ! in_array($decoded['verdict'], self::VERDICTS, true)) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini verdict was invalid.');
        }
        if (! is_string($decoded['threat_category']) || ! in_array($decoded['threat_category'], self::CATEGORIES, true)) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini threat category was invalid.');
        }

        $chain = $decoded['analysis_chain'];
        if (! is_array($chain) || $chain === [] || count($chain) > self::MAX_CHAIN_ITEMS) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini analysis chain was invalid.');
        }
        foreach ($chain as $step) {
            if (! is_string($step) || trim($step) === '' || mb_strlen($step) > self::MAX_CHAIN_ITEM_LENGTH) {
                throw new GeminiAnalysisException('invalid_schema', true, 'Gemini analysis chain item was invalid.');
            }
        }
        if (! is_string($decoded['final_reasoning']) || trim($decoded['final_reasoning']) === '' || mb_strlen($decoded['final_reasoning']) > self::MAX_REASONING_LENGTH) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini final reasoning was invalid.');
        }

        return [
            'risk_score' => $decoded['risk_score'],
            'verdict' => $decoded['verdict'],
            'threat_category' => $decoded['threat_category'],
            'analysis_chain' => array_values($chain),
            'final_reasoning' => $decoded['final_reasoning'],
        ];
    }

    /** @return array{vendor_name: ?string, invoice_amount: ?string, bank_routing_number: ?string, bank_account_number: ?string, is_payment_request: bool} */
    public function validateFinancialAttachment(array $payload): array
    {
        $decoded = $this->decodeCandidate($payload);

        if (! array_key_exists('is_payment_request', $decoded) || ! is_bool($decoded['is_payment_request'])) {
            throw new GeminiAnalysisException('invalid_schema', true, 'Gemini payment-request value was invalid.');
        }

        $result = ['is_payment_request' => $decoded['is_payment_request']];
        foreach (['vendor_name', 'invoice_amount', 'bank_routing_number', 'bank_account_number'] as $field) {
            $value = $decoded[$field] ?? null;
            if ($value !== null && (! is_string($value) || mb_strlen($value) > 255)) {
                throw new GeminiAnalysisException('invalid_schema', true, "Gemini {$field} was invalid.");
            }
            $result[$field] = $value === null || trim($value) === '' ? null : trim($value);
        }

        return $result;
    }

    /** @return array<string, mixed> */
    private function decodeCandidate(array $payload): array
    {
        if (($payload['promptFeedback']['blockReason'] ?? null) || ($payload['candidates'][0]['finishReason'] ?? null) === 'SAFETY') {
            throw new GeminiAnalysisException('safety_blocked', false, 'Gemini blocked the response for safety.');
        }

        $text = $payload['candidates'][0]['content']['parts'][0]['text'] ?? null;
        if (! is_string($text) || trim($text) === '') {
            throw new GeminiAnalysisException('invalid_response', true, 'Gemini response had no candidate text.');
        }

        $text = trim($text);
        if (preg_match('/^```(?:json)?\s*(.*?)\s*```$/is', $text, $matches) === 1) {
            $text = trim($matches[1]);
        }
        $decoded = json_decode($text, true);

        if (! is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
            throw new GeminiAnalysisException('invalid_response', true, 'Gemini response was not a complete JSON object.');
        }

        return $decoded;
    }
}
