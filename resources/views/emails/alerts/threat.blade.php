<x-mail::message>
# 🛡️ Threat Neutralized & Quarantined

The Active Defense system successfully intercepted a high-risk email before it could reach the inbox.

**Target User:** {{ $emailDetails['user_email'] }}
**Threat Subject:** {{ $emailDetails['subject'] }}

<x-mail::panel>
**Risk Score:** {{ $analysis['risk_score'] }}% - {{ strtoupper($analysis['severity']) }}
**Detection Engine:** {{ $analysis['detection_layer'] }}
</x-mail::panel>

**Analysis/Reason:** _{{ $analysis['reason'] ?? 'Caught by manual security rules.' }}_

<x-mail::button :url="config('app.url') . '/dashboard'">
View Dashboard
</x-mail::button>

Stay secure,<br>
**{{ config('app.name') }} Security Operations**
</x-mail::message>
