<?php

use Illuminate\Database\Migrations\Migration;

return new class extends Migration
{
    public function up(): void
    {
        // Retained for migration history. User bootstrap now belongs to explicit seed/command flows.
    }

    public function down(): void
    {
        // No schema or user data to reverse.
    }
};
