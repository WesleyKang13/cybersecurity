<?php

namespace App\Services;

use App\Models\User;
use Google\Client;
use Google\Service\Gmail;
use Illuminate\Support\Facades\Http;

class GmailService
{
    protected $client;

    public function __construct(User $user)
    {
        $this->client = new Client();
        $this->client->setClientId(config('services.google.client_id'));
        $this->client->setClientSecret(config('services.google.client_secret'));

        // Load the token from our database
        $tokenRecord = $user->token;

        if (!$tokenRecord) {
            throw new \Exception("User is not connected to Gmail.");
        }

        // Set the access token
        $this->client->setAccessToken([
            'access_token' => $tokenRecord->access_token,
            'refresh_token' => $tokenRecord->refresh_token,
            'expires_in' => $tokenRecord->expires_at->diffInSeconds(now(), true),
            'created' => $tokenRecord->updated_at->timestamp,
        ]);

        // Auto-refresh if expired
        if ($this->client->isAccessTokenExpired()) {
            if ($this->client->getRefreshToken()) {
                $newToken = $this->client->fetchAccessTokenWithRefreshToken($this->client->getRefreshToken());

                // Save new token to DB so we stay logged in
                $tokenRecord->update([
                    'access_token' => $newToken['access_token'],
                    'expires_at' => now()->addSeconds($newToken['expires_in']),
                ]);
            }
        }
    }

    /**
     * Get basic stats for the Dashboard
     */
    public function getProfileStats()
    {
        $service = new Gmail($this->client);

        // Get Profile (Total Messages)
        $profile = $service->users->getProfile('me');

        return [
            'email' => $profile->getEmailAddress(),
            'total_messages' => $profile->getMessagesTotal(),
            'history_id' => $profile->getHistoryId(),
        ];
    }

    /**
     * Fetch the last 10 emails from the Inbox
     */
    public function fetchLatestEmails($limit = 10)
    {
        $service = new Gmail($this->client);

        // 1. List the Message IDs
        $results = $service->users_messages->listUsersMessages('me', [
            'maxResults' => $limit,
            'labelIds' => ['INBOX'], // Only check Inbox
        ]);

        $messages = [];

        // 2. Loop through and get details for each email
        if ($results->getMessages()) {
            foreach ($results->getMessages() as $message) {
                // Get full details (snippet, headers)
                $details = $service->users_messages->get('me', $message->getId());

                // Extract Subject and Sender from Headers
                $headers = $details->getPayload()->getHeaders();
                $subject = 'No Subject';
                $from = 'Unknown';

                foreach ($headers as $header) {
                    if ($header->getName() === 'Subject') $subject = $header->getValue();
                    if ($header->getName() === 'From') $from = $header->getValue();
                }

                $messages[] = [
                    'id' => $message->getId(),
                    'snippet' => $details->getSnippet(),
                    'subject' => $subject,
                    'from' => $from,
                ];
            }
        }

        return $messages;
    }
}
