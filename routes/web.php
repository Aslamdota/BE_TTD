<?php

use Illuminate\Support\Facades\Route;
use L5Swagger\Http\Controllers\SwaggerController;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/docs', function () {
    return response()->file(storage_path('api-docs/api-docs.json'));
})->name('l5-swagger.default.docs');



