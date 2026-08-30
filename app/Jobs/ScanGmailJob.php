<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Mail\ThreatAlertMail;
use App\Models\User;
use App\Services\EmailScannerService;
use App\Services\EmailOriginService;
use App\Services\GmailService;
use App\Services\LinkExtractionService;
use Google\Client;
use Google\Service\Gmail;
use Google\Service\Gmail\ModifyMessageRequest;
use GuzzleHttp\Client as GuzzleClient;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\Middleware\RateLimited;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Throwable;

class ScanGmailJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private const CONNECT_TIMEOUT_SECONDS = 5;
    private const REQUEST_TIMEOUT_SECONDS = 10;

    protected User $user;

    public int $tries = 3;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function middleware(): array
    {
        return [new RateLimited('gemini-api')];
    }

    public function handle(
        EmailScannerService $scanner,
        EmailOriginService $emailOriginService,
        LinkExtractionService $linkExtractionService
    ): void
    {
        if (!$this->user->google_access_token && !$this->user->google_refresh_token) {
            return;
        }

        try {
            $gmail = new GmailService($this->user);
            $emails = $gmail->fetchLatestEmails(5);
            $this->user->refresh();
        } catch (Throwable $e) {
            Log::error("Gmail sync failed for user {$this->user->id}: {$e->getMessage()}");

            return;
        }

        foreach ($emails as $email) {
            try {
                $extractedLinks = $linkExtractionService->extractAndInspect(
                    (string) ($email['html_body'] ?? ''),
                    (string) ($email['body'] ?? $email['snippet'] ?? '')
                );

                ['record' => $scannedEmail, 'created' => $created] = $scanner->scanAndStore($this->user, [
                    'google_message_id' => (string) ($email['id'] ?? ''),
                    'subject' => (string) ($email['subject'] ?? ''),
                    'sender' => (string) ($email['from'] ?? ''),
                    'snippet' => (string) ($email['snippet'] ?? ''),
                    'body' => (string) ($email['body'] ?? $email['snippet'] ?? ''),
                    'html_body' => (string) ($email['html_body'] ?? ''),
                    'extracted_links' => $extractedLinks,
                    'pdf_attachments' => $email['pdf_attachments'] ?? [],
                ]);

                if (!$created) {
                    continue;
                }

                if ($scannedEmail->risk_score >= 90 && !empty($email['raw_headers'])) {
                    $scannedEmail->update([
                        'origin_trace' => $emailOriginService->trace((string) $email['raw_headers']),
                    ]);
                }

                if ($scannedEmail->risk_score >= 90 && $this->user->auto_quarantine) {
                    try {
                        $gmailService = $this->buildAuthenticatedGmailService();
                        $response = $gmailService->users_messages->modify(
                            'me',
                            (string) ($email['id'] ?? ''),
                            new ModifyMessageRequest([
                                'addLabelIds' => ['SPAM'],
                                'removeLabelIds' => ['INBOX'],
                            ])
                        );

                        if ($response->getId()) {
                            Log::info("🛡️ Active Defense: Quarantined Email {$email['id']} for User {$this->user->id}");
                            $scannedEmail->update(['is_quarantined' => true]);
                            Mail::to($this->user->email)->send(new ThreatAlertMail(
                                [
                                    'subject' => (string) ($email['subject'] ?? ''),
                                    'user_email' => $this->user->email,
                                ],
                                [
                                    'is_threat' => $scannedEmail->is_threat,
                                    'detection_layer' => $scannedEmail->detection_layer,
                                    'severity' => $scannedEmail->severity,
                                    'risk_score' => $scannedEmail->risk_score,
                                    'reason' => $scannedEmail->reason,
                                ]
                            ));
                        } else {
                            Log::error("Failed to auto-quarantine: Gmail modify call returned an unexpected response for message {$email['id']}.");
                        }
                    } catch (Throwable $e) {
                        Log::error("Auto-Quarantine Exception: {$e->getMessage()}");
                    }
                }
            } catch (Throwable $e) {
                Log::error("Failed to process Gmail message {$email['id']} for user {$this->user->id}: {$e->getMessage()}");
            }
        }
    }

    private function buildAuthenticatedGmailService(): Gmail
    {
        $this->user->refresh();

        $client = new Client();
        $client->setClientId(config('services.google.client_id'));
        $client->setClientSecret(config('services.google.client_secret'));
        $client->setHttpClient(new GuzzleClient([
            'connect_timeout' => self::CONNECT_TIMEOUT_SECONDS,
            'timeout' => self::REQUEST_TIMEOUT_SECONDS,
        ]));
        $client->setAccessToken(array_filter([
            'access_token' => $this->user->google_access_token,
            'refresh_token' => $this->user->google_refresh_token,
        ]));

        if (
            empty($this->user->google_access_token)
            || ($this->user->google_token_expires_at && $this->user->google_token_expires_at->isPast())
        ) {
            $this->refreshGoogleAccessToken($client);
        }

        return new Gmail($client);
    }

    private function refreshGoogleAccessToken(Client $client): void
    {
        $refreshToken = $this->user->google_refresh_token;

        if (!$refreshToken) {
            throw new \RuntimeException("No Google refresh token found for user {$this->user->id}.");
        }

        $newToken = $client->fetchAccessTokenWithRefreshToken($refreshToken);

        if (isset($newToken['error'])) {
            throw new \RuntimeException($newToken['error_description'] ?? $newToken['error']);
        }

        $this->user->update([
            'google_access_token' => $newToken['access_token'] ?? $this->user->google_access_token,
            'google_refresh_token' => $refreshToken,
            'google_token_expires_at' => isset($newToken['expires_in'])
                ? now()->addSeconds((int) $newToken['expires_in'])
                : $this->user->google_token_expires_at,
        ]);

        $this->user->refresh();
        $client->setAccessToken(array_filter([
            'access_token' => $this->user->google_access_token,
            'refresh_token' => $this->user->google_refresh_token,
        ]));
    }
}
