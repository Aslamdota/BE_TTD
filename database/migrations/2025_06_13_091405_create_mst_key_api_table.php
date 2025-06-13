<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('mst_key_api', function (Blueprint $table) {
            $table->id();
            $table->foreignId('api_id')->constrained('mst_api')->onDelete('cascade');
            $table->string('api_key');
            $table->string('api_secret');
            $table->timestamps();

            $table->index('api_key');
        });
    }

    public function down()
    {
        Schema::dropIfExists('mst_key_api');
    }
};
