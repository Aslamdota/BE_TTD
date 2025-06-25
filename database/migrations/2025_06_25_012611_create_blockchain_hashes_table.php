<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blockchain_hashes', function (Blueprint $table) {
            $table->id();
            $table->string('hash')->unique();
            $table->string('type')->nullable(); // contoh: 'signature', 'document', dsb
            $table->unsignedBigInteger('user_id')->nullable();
            $table->unsignedBigInteger('document_id')->nullable();
            $table->string('blockchain_tx')->nullable(); // tx hash jika ada
            $table->timestamp('signed_at')->nullable();
            $table->timestamps();

            $table->index('hash');
            $table->foreign('user_id')->references('id')->on('users')->nullOnDelete();
            $table->foreign('document_id')->references('id')->on('documents')->nullOnDelete();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blockchain_hashes');
    }
};
