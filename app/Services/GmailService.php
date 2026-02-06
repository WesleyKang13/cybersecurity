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

        // FIX: The token is now a simple string on the User model
        // We do NOT need to look up a separate database record anymore.
        $accessToken = $user->token;

        if (!$accessToken) {
            throw new \Exception("User {$user->id} has no Google token.");
        }

        // format the array exactly how Google Client expects it
        $this->client->setAccessToken([
            'access_token'  => $accessToken,
            'refresh_token' => null,   // We aren't using refresh tokens yet
            'expires_in'    => 3600,   // Default to 1 hour
            'created'       => time(), // Assume it's valid now
        ]);
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
                    'ippet' => $details->getSnippet(),
                    'subject' => $subject,
                    'from' => $from,
                ];
            }
        }

        return $messages;
    }
}
