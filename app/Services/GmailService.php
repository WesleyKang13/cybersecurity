<?php

namespace App\Services;

use App\Models\User;
use Google\Client;
use Google\Service\Gmail;

class GmailService
{
    protected $client;
    protected $user;

    public function __construct(User $user)
    {
        $this->user = $user;
        $this->client = new Client();
        $this->client->setClientId(config('services.google.client_id'));
        $this->client->setClientSecret(config('services.google.client_secret'));

        // Load the full token array (Access + Refresh + Expiry)
        $tokenData = $user->token;

        if (!$tokenData) {
            throw new \Exception("User {$user->id} has no Google token.");
        }

        // Set the token on the client
        $this->client->setAccessToken($tokenData);
    }

    /**
     * Fetch the latest emails with "Auto-Heal" capability
     */
    public function fetchLatestEmails($limit = 10)
    {
        // If the library thinks the token is expired (based on 'created' time),
        // we refresh it immediately and SAVE it to the DB before doing anything else.
        if ($this->client->isAccessTokenExpired()) {
            $this->refreshAccessToken();
        }
        
        // 1. Initialize the service
        $service = new Gmail($this->client);

        try {
            // 2. Try to fetch messages normally
            return $this->executeListMessages($service, $limit);

        } catch (\Google\Service\Exception $e) {

            // 3. Catch "401 Unauthorized" (Token Expired)
            if ($e->getCode() == 401) {

                // 4. Refresh the token using the Master Key
                $this->refreshAccessToken();

                // 5. Re-initialize the service with the NEW token
                $service = new Gmail($this->client);

                // 6. Retry the fetch one last time
                return $this->executeListMessages($service, $limit);
            }

            // If it's a different error (e.g., 403 Permission Denied), throw it up
            throw $e;
        }
    }

    /**
     * Helper: The actual API call logic
     */
    private function executeListMessages($service, $limit)
    {
        $results = $service->users_messages->listUsersMessages('me', [
            'maxResults' => $limit,
            'labelIds' => ['INBOX']
        ]);

        $messages = [];
        if ($results->getMessages()) {
            foreach ($results->getMessages() as $message) {
                // Fetch full details (Snippet, Headers)
                $details = $service->users_messages->get('me', $message->getId());

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

    /**
     * CRITICAL: Refresh the token and save it safely
     */
    private function refreshAccessToken()
    {
        // 1. Get the Refresh Token (The "Master Key")
        // It might be in the Client, or we might need to grab it from the User DB manually.
        $refreshToken = $this->client->getRefreshToken();

        if (!$refreshToken && isset($this->user->token['refresh_token'])) {
            $refreshToken = $this->user->token['refresh_token'];
        }

        if (!$refreshToken) {
            throw new \Exception("Refresh failed: No refresh_token found. User {$this->user->id} must reconnect Google.");
        }

        // 2. Ask Google for a new Access Token
        // This returns an array like ['access_token' => '...', 'expires_in' => 3600, 'created' => ...]
        // Note: It usually DOES NOT contain the 'refresh_token' again.
        $newToken = $this->client->fetchAccessTokenWithRefreshToken($refreshToken);

        if (isset($newToken['error'])) {
            throw new \Exception("Google Refresh Error: " . ($newToken['error_description'] ?? $newToken['error']));
        }

        // 3. Update the Client with the new access token
        $this->client->setAccessToken($newToken);

        // 4. MERGE & SAVE (Crucial Step)
        // We must merge the NEW token data with the OLD token data.
        // If we don't, we will lose the 'refresh_token' and the user will have to login again in 1 hour.
        $oldToken = $this->user->token ?? [];

        // Ensure the refresh token is preserved in the new array
        if (!isset($newToken['refresh_token'])) {
            $newToken['refresh_token'] = $refreshToken;
        }

        $finalToken = array_merge($oldToken, $newToken);

        // 5. Save to Database
        $this->user->update(['token' => $finalToken]);
    }
}
