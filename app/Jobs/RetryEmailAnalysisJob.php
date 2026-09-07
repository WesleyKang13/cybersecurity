<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Mail\ThreatAlertMail;
use App\Models\User;
use App\Services\EmailScannerService;
use App\Services\GmailService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class RetryEmailAnalysisJob implements ShouldBeUnique, ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 1;

    public function __construct(public int $userId, public string $googleMessageId) {}

    public function uniqueId(): string
    {
        return "{$this->userId}:{$this->googleMessageId}";
    }

    public function handle(EmailScannerService $scanner): void
    {
        $user = User::find($this->userId);

        if ($user !== null) {
            $record = $scanner->retryIncomplete($user, $this->googleMessageId);

            if ($record !== null && $record->analysis_status === 'completed' && $record->risk_score >= 90 && ! $record->is_quarantined && $user->auto_quarantine) {
                try {
                    if ((new GmailService($user))->quarantineMessage($this->googleMessageId)) {
                        $record->update(['is_quarantined' => true]);
                    }
                } catch (\Throwable $exception) {
                    Log::warning('Completed retry could not quarantine Gmail message.', ['user_id' => $user->id, 'scan_id' => $record->id]);
                }
            }

            if ($record !== null && $record->analysis_status === 'completed' && $record->risk_score >= 90 && $record->is_quarantined
                && $record->newQuery()->whereKey($record->id)->where('user_id', $user->id)->whereNull('alert_sent_at')->update(['alert_sent_at' => now()]) === 1) {
                Mail::to($user->email)->send(new ThreatAlertMail([
                    'subject' => $record->subject,
                    'user_email' => $user->email,
                ], [
                    'is_threat' => $record->is_threat,
                    'detection_layer' => $record->detection_layer,
                    'severity' => $record->severity,
                    'risk_score' => $record->risk_score,
                    'reason' => $record->reason,
                ]));
            }
        }
    }
}
