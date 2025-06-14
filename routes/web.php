<?php

use Illuminate\Support\Facades\Route;
use L5Swagger\Http\Controllers\SwaggerController;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/docs', [SwaggerController::class, 'docs'])->name('l5-swagger.default.docs');


