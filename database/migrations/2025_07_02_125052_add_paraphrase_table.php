<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    
    public function up(): void
    {
        Schema::table('passkeys', function (Blueprint $table) {
            $table->string('paraphrase')->nullable()->after('private_key');
        });
    }

    public function down(): void
    {
        Schema::table('passkeys', function (Blueprint $table) {
            $table->dropColumn('paraphrase');
        });
    }
};
