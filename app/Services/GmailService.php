<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\User;
use App\Support\GmailAuthenticationEvidence;
use Google\Client;
use Google\Service\Gmail;
use Google\Service\Exception as GoogleServiceException;
use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Support\Facades\Log;
use Throwable;

class GmailService
{
    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const REQUEST_TIMEOUT_SECONDS = 10;

    protected Client $client;
    protected User $user;

    public function __construct(User $user)
    {
        $this->user = $user;
        $this->client = new Client();
        $this->client->setClientId(config('services.google.client_id'));
        $this->client->setClientSecret(config('services.google.client_secret'));
        $this->client->setHttpClient(new GuzzleClient([
            'connect_timeout' => self::CONNECT_TIMEOUT_SECONDS,
            'timeout' => self::REQUEST_TIMEOUT_SECONDS,
        ]));

        if (empty($user->google_access_token) && empty($user->google_refresh_token)) {
            throw new \Exception("User {$user->id} has no Google OAuth tokens.");
        }

        $this->syncClientAccessToken();
    }

    /**
     * Fetch the latest emails with "Auto-Heal" capability
     */
    public function fetchLatestEmails(int $limit = 10): array
    {
        $this->ensureValidAccessToken();

        $service = new Gmail($this->client);

        try {
            return $this->executeListMessages($service, $limit);
        } catch (GoogleServiceException $e) {
            if ($e->getCode() === 401) {
                $this->refreshAccessToken();
                $service = new Gmail($this->client);

                return $this->executeListMessages($service, $limit);
            }

            throw $e;
        }
    }

    /**
     * Helper: The actual API call logic
     */
    private function executeListMessages(Gmail $service, int $limit): array
    {
        $results = $service->users_messages->listUsersMessages('me', [
            'maxResults' => $limit,
            'labelIds' => ['INBOX'],
        ]);

        $messages = [];
        if ($results->getMessages()) {
            foreach ($results->getMessages() as $message) {
                try {
                    $details = $service->users_messages->get('me', $message->getId());
                    $payload = $details->getPayload();
                    $headers = $payload?->getHeaders() ?? [];
                    $subject = 'No Subject';
                    $from = 'Unknown';

                    foreach ($headers as $header) {
                        if ($header->getName() === 'Subject') {
                            $subject = $header->getValue();
                        }

                        if ($header->getName() === 'From') {
                            $from = $header->getValue();
                        }
                    }

                    $messages[] = [
                        'id' => (string) $message->getId(),
                        'snippet' => (string) $details->getSnippet(),
                        'subject' => $subject,
                        'from' => $from,
                        'body' => $this->extractMessageBody($payload),
                        'html_body' => $this->extractHtmlBody($payload),
                        'raw_headers' => $this->formatRawHeaders($headers),
                        'gmail_authentication' => GmailAuthenticationEvidence::fromGmailHeaders($headers),
                        'pdf_attachments' => $this->extractPdfAttachments($service, (string) $message->getId(), $payload),
                    ];
                } catch (Throwable $e) {
                    Log::warning("Skipping Gmail message {$message->getId()} due to parse error: {$e->getMessage()}");
                }
            }
        }

        return $messages;
    }

    private function extractMessageBody(mixed $payload): string
    {
        $plainText = $this->extractBodyByMimeType($payload, 'text/plain');

        if ($plainText !== '') {
            return $plainText;
        }

        $htmlBody = $this->extractHtmlBody($payload);

        return $htmlBody !== ''
            ? trim(html_entity_decode(strip_tags($htmlBody), ENT_QUOTES | ENT_HTML5, 'UTF-8'))
            : '';
    }

    private function extractHtmlBody(mixed $payload): string
    {
        return $this->extractBodyByMimeType($payload, 'text/html');
    }

    private function extractBodyByMimeType(mixed $payload, string $targetMimeType): string
    {
        if (!$payload) {
            return '';
        }

        if ($payload->getMimeType() === $targetMimeType && $payload->getBody()?->getData()) {
            return $this->decodeBase64Url($payload->getBody()->getData());
        }

        foreach ($payload->getParts() ?? [] as $part) {
            $body = $this->extractBodyByMimeType($part, $targetMimeType);

            if ($body !== '') {
                return $body;
            }
        }

        return '';
    }

    /**
     * @return array<int, array{filename: string, mime_type: string, base64_data: string}>
     */
    private function extractPdfAttachments(Gmail $service, string $messageId, mixed $payload): array
    {
        if (!$payload) {
            return [];
        }

        $attachments = [];

        if ($payload->getMimeType() === 'application/pdf') {
            $attachmentBody = $payload->getBody();
            $attachmentData = '';

            if ($attachmentBody?->getAttachmentId()) {
                $fetchedAttachment = $service->users_messages_attachments->get('me', $messageId, $attachmentBody->getAttachmentId());
                $attachmentData = $this->base64UrlToBase64((string) $fetchedAttachment->getData());
            } elseif ($attachmentBody?->getData()) {
                $attachmentData = $this->base64UrlToBase64((string) $attachmentBody->getData());
            }

            if ($attachmentData !== '') {
                $attachments[] = [
                    'filename' => $payload->getFilename() ?: 'attachment.pdf',
                    'mime_type' => 'application/pdf',
                    'base64_data' => $attachmentData,
                ];
            }
        }

        foreach ($payload->getParts() ?? [] as $part) {
            $attachments = array_merge($attachments, $this->extractPdfAttachments($service, $messageId, $part));
        }

        return $attachments;
    }

    private function decodeBase64Url(string $data): string
    {
        return base64_decode($this->base64UrlToBase64($data)) ?: '';
    }

    private function base64UrlToBase64(string $data): string
    {
        $normalized = strtr($data, '-_', '+/');
        $padding = strlen($normalized) % 4;

        if ($padding > 0) {
            $normalized .= str_repeat('=', 4 - $padding);
        }

        return $normalized;
    }

    private function formatRawHeaders(array $headers): string
    {
        $lines = [];

        foreach ($headers as $header) {
            $lines[] = $header->getName() . ': ' . $header->getValue();
        }

        return implode("\r\n", $lines);
    }

    /**
     * Keep the client synchronized with the encrypted token columns.
     */
    private function syncClientAccessToken(): void
    {
        $tokenPayload = array_filter([
            'access_token' => $this->user->google_access_token,
            'refresh_token' => $this->user->google_refresh_token,
        ]);

        if ($this->user->google_token_expires_at) {
            $secondsUntilExpiry = max(0, now()->diffInSeconds($this->user->google_token_expires_at, false));
            $tokenPayload['created'] = now()->timestamp;
            $tokenPayload['expires_in'] = $secondsUntilExpiry;
        }

        $this->client->setAccessToken($tokenPayload);
    }

    /**
     * Refresh automatically before Gmail API requests.
     */
    private function ensureValidAccessToken(): void
    {
        if (empty($this->user->google_access_token) || $this->client->isAccessTokenExpired()) {
            $this->refreshAccessToken();
        }
    }

    /**
     * Refresh the access token using the stored encrypted refresh token.
     */
    private function refreshAccessToken(): void
    {
        $refreshToken = $this->user->google_refresh_token;

        if (!$refreshToken) {
            throw new \Exception("Refresh failed: No Google refresh token found. User {$this->user->id} must reconnect Google.");
        }

        $newToken = $this->client->fetchAccessTokenWithRefreshToken($refreshToken);

        if (isset($newToken['error'])) {
            throw new \Exception("Google Refresh Error: " . ($newToken['error_description'] ?? $newToken['error']));
        }

        $refreshedAccessToken = $newToken['access_token'] ?? $this->user->google_access_token;
        $newExpiry = isset($newToken['expires_in'])
            ? now()->addSeconds((int) $newToken['expires_in'])
            : $this->user->google_token_expires_at;

        $this->user->update([
            'google_access_token' => $refreshedAccessToken,
            'google_token_expires_at' => $newExpiry,
        ]);

        $this->user->refresh();
        $this->syncClientAccessToken();
    }
}
