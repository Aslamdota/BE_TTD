<?php

use Illuminate\Support\Facades\Route;
use L5Swagger\Http\Controllers\SwaggerController;

Route::get('/', function () {
    return view('welcome');
});

Route::middleware('swagger.protect')->group(function () {   
    Route::get('/docs', [SwaggerController::class, 'docs']);

    Route::get('/api/docs-json', [SwaggerController::class, 'docsJson'])->name('l5-swagger.default.docs');
});





