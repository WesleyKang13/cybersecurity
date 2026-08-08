<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\EmailScannerService;
use App\Models\User;
use ReflectionMethod;

class TestEmailScanner extends Command
{
    protected $signature = 'scanner:test {pdf_path} {--sender=wesleykjr13@gmail.com}';
    protected $description = 'Directly test email scanner with a local PDF attachment';

    public function handle(EmailScannerService $scanner)
    {
        $pdfPath = $this->argument('pdf_path');
        $sender = $this->option('sender');

        if (!file_exists($pdfPath)) {
            $this->error("PDF file not found at: {$pdfPath}");
            return;
        }

        // Get an existing user or mock one for the database relationship
        $user = User::first() ?? User::factory()->make(['id' => 1]);

        // Construct the array format expected by scanAndStore()
        $emailPayload = [
            'google_message_id' => 'cli-test-' . microtime(true),
            'subject' => 'Updated Payment Details for Project X',
            'sender' => $sender,
            'snippet' => 'Please find attached payment instructions.',
            'body' => 'Hi Team, Please find the attached payment instructions for our recent consulting services. Best regards, Wesley Kang',
            'pdf_attachments' => [
                [
                    'mime_type' => 'application/pdf',
                    'filename' => basename($pdfPath),
                    'base64_data' => base64_encode(file_get_contents($pdfPath)),
                ]
            ]
        ];

        $this->info("Scanning email with PDF [{$pdfPath}] from {$sender}...");

        // --- DEBUG STEP: Inspect Private Attachment Extraction ---
        try {
            $reflection = new ReflectionMethod($scanner, 'analyzeFinancialAttachments');
            $reflection->setAccessible(true);

            $financialResults = $reflection->invoke($scanner, $emailPayload['pdf_attachments']);

            $this->warn('--- EXTRACTED PDF FINANCIAL DATA ---');
            $this->line(json_encode($financialResults, JSON_PRETTY_PRINT));
            $this->newLine();
        } catch (\Exception $e) {
            $this->error("Failed to inspect PDF context: " . $e->getMessage());
        }

        // --- MAIN PIPELINE: Run Full Scanner Funnel ---
        $result = $scanner->scanAndStore($user, $emailPayload);

        $this->info('--- SCAN RESULT ---');
        $this->line(json_encode($scanner->formatResult($result['record'], $result['created']), JSON_PRETTY_PRINT));
    }
}
