<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('multi_signatures', function (Blueprint $table) {
            $table->id();
            $table->foreignId('document_id')->constrained();
            $table->json('signers_order'); // Array of user IDs in signing order
            $table->integer('current_signer_index')->default(0);
            $table->string('status')->default('pending');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('multi_signatures');
    }
};
