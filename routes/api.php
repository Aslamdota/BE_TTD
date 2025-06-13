<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DocumentController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\BlockchainController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Public routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/verify', [DocumentController::class, 'verify']);

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'user']);

    // Documents
    Route::post('/documents/upload', [DocumentController::class, 'upload']);
    Route::post('/documents/{documentId}/sign', [DocumentController::class, 'sign']);
    Route::get('/documents', [DocumentController::class, 'list']);
    Route::get('/documents/pending', [DocumentController::class, 'pendingSignatures']);

    // Blockchain
    Route::post('/blockchain/store', [BlockchainController::class, 'storeHash']);
    Route::post('/blockchain/verify', [BlockchainController::class, 'verifyHash']);

    // Admin routes
    Route::prefix('admin')->middleware('can:admin')->group(function () {
        // User management
        Route::get('/users', [AdminController::class, 'listUsers']);
        Route::post('/users', [AdminController::class, 'createUser']);
        Route::put('/users/{userId}', [AdminController::class, 'updateUser']);
        Route::delete('/users/{userId}', [AdminController::class, 'deleteUser']);

        // Role management
        Route::get('/roles', [AdminController::class, 'listRoles']);
        Route::post('/roles', [AdminController::class, 'createRole']);

        // API management
        Route::get('/apis', [AdminController::class, 'listApis']);
        Route::post('/apis', [AdminController::class, 'createApi']);
        Route::post('/apis/{apiId}/keys', [AdminController::class, 'generateApiKey']);
        Route::delete('/keys/{keyId}', [AdminController::class, 'revokeApiKey']);

        // Menu management
        Route::get('/menus', [AdminController::class, 'listMenus']);
        Route::post('/menus', [AdminController::class, 'createMenu']);
        Route::put('/menus/{menuId}', [AdminController::class, 'updateMenu']);
        Route::delete('/menus/{menuId}', [AdminController::class, 'deleteMenu']);
    });
});
