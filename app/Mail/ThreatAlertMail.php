<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ThreatAlertMail extends Mailable
{
    use Queueable, SerializesModels;

    public $emailDetails;
    public $analysis;

    public function __construct($emailDetails, $analysis)
    {
        $this->emailDetails = $emailDetails;
        $this->analysis = $analysis;
    }

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: '🚨 CRITICAL: Threat Neutralized & Quarantined',
        );
    }

    public function content(): Content
    {
        return new Content(
            markdown: 'emails.alerts.threat',
        );
    }
}
