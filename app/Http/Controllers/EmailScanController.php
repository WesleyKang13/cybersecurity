<?php

namespace App\Http\Controllers;

use App\Services\EmailScannerService;
use Illuminate\Http\Request;

class EmailScanController extends Controller
{
    public function store(Request $request, EmailScannerService $scanner)
    {
        $validated = $request->validate([
            'emails' => ['required', 'array', 'min:1'],
            'emails.*.google_message_id' => ['required', 'string', 'max:255'],
            'emails.*.subject' => ['nullable', 'string'],
            'emails.*.sender' => ['nullable', 'string'],
            'emails.*.snippet' => ['nullable', 'string'],
            'emails.*.body' => ['nullable', 'string'],
            'emails.*.pdf_attachments' => ['sometimes', 'array'],
            'emails.*.pdf_attachments.*.filename' => ['nullable', 'string'],
            'emails.*.pdf_attachments.*.mime_type' => ['nullable', 'string'],
            'emails.*.pdf_attachments.*.base64_data' => ['nullable', 'string'],
        ]);

        $results = collect($validated['emails'])
            ->map(function (array $email) use ($request, $scanner) {
                ['record' => $record, 'created' => $created] = $scanner->scanAndStore($request->user(), $email);

                return $scanner->formatResult($record, $created);
            })
            ->values();

        return response()->json([
            'results' => $results,
        ]);
    }
}
