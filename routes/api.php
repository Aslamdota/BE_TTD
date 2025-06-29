<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\ApiKeyController;
use App\Http\Controllers\DocumentController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\BlockchainController;
use Illuminate\Foundation\Auth\EmailVerificationRequest;

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

/*------------------------------------------
| AUTHENTICATION ROUTES
|------------------------------------------*/
Route::prefix('auth')->group(function () {
    // Public auth endpoints
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/forgot-password', [AuthController::class, 'forgotPassword']);
    Route::post('/reset-password', [AuthController::class, 'resetPassword']);
    Route::post('/send-otp', [AuthController::class, 'sendOtp']);
    Route::post('/verify-otp', [AuthController::class, 'verifyOtp']);
    
    // Protected auth endpoints
    Route::middleware('auth:sanctum')->group(function () {
        Route::get('/check-session', [AuthController::class, 'checkSession']);
        Route::get('/active-session', [AuthController::class, 'activeSession']);
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::post('/force-logout', [AuthController::class, 'forceLogout']);
        Route::post('/refresh-token', [AuthController::class, 'refreshToken']);
        Route::get('/user', [AuthController::class, 'user']);
        Route::put('/profile', [AuthController::class, 'updateProfile']);
        Route::post('/change-password', [AuthController::class, 'changePassword']);
    });
});

/*------------------------------------------
| DOCUMENT ROUTES
|------------------------------------------*/
Route::prefix('documents')->group(function () {
    // Public document endpoints
    Route::post('/verify', [DocumentController::class, 'verify']);
    
    // Protected document endpoints
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/upload', [DocumentController::class, 'upload']);
        Route::post('/{documentId}/sign', [DocumentController::class, 'sign']);
        Route::get('/', [DocumentController::class, 'list']);
        Route::get('/pending', [DocumentController::class, 'pendingSignatures']);
    });
});

/*------------------------------------------
| BLOCKCHAIN ROUTES
|------------------------------------------*/
Route::prefix('blockchain')->group(function () {
    // Public blockchain endpoints
    Route::post('/verify', [BlockchainController::class, 'verifyDocumentHash']);
    Route::post('/verify-signature', [BlockchainController::class, 'verifySignatureHash']);
    
    // Protected blockchain endpoints
    Route::middleware('auth:sanctum')->group(function () {
        Route::post('/store', [BlockchainController::class, 'storeHash']);
    });
});

/*------------------------------------------
| ADMIN ROUTES
|------------------------------------------*/
Route::prefix('admin')->middleware(['auth:sanctum', 'can:admin'])->group(function () {
    // User Management
    Route::get('/users', [AdminController::class, 'listUsers']);
    Route::post('/users', [AdminController::class, 'createUser']);
    Route::put('/users/{userId}', [AdminController::class, 'updateUser']);
    Route::delete('/users/{userId}', [AdminController::class, 'deleteUser']);
    Route::put('/users/{userId}/password', [AdminController::class, 'adminChangeUserPassword']);
    Route::post('/import-dosen', [AdminController::class, 'importDosen']);

    // Role Management
    Route::get('/roles', [AdminController::class, 'listRoles']);
    Route::post('/roles', [AdminController::class, 'createRole']);

    // API Management
    Route::get('/apis', [AdminController::class, 'listApis']);
    Route::post('/apis', [AdminController::class, 'createApi']);
    Route::post('/apis/{apiId}/keys', [AdminController::class, 'generateApiKey']);
    Route::delete('/keys/{keyId}', [AdminController::class, 'revokeApiKey']);

    // Menu Management
    Route::get('/menus', [AdminController::class, 'listMenus']);
    Route::post('/menus', [AdminController::class, 'createMenu']);
    Route::put('/menus/{menuId}', [AdminController::class, 'updateMenu']);
    Route::delete('/menus/{menuId}', [AdminController::class, 'deleteMenu']);

    // Email Verification
    Route::get('/email/verify/{id}/{hash}', function (EmailVerificationRequest $request) {
        $request->fulfill();
        return response()->json(['message' => 'Email verified!']);
    })->middleware(['signed'])->name('verification.verify');

    Route::post('/email/verification-notification', function (Request $request) {
        $request->user()->sendEmailVerificationNotification();
        return response()->json(['message' => 'Verification link sent!']);
    })->middleware(['throttle:6,1']);
});

/*------------------------------------------
| TEST ROUTE
|------------------------------------------*/
Route::middleware('auth:sanctum')->get('/test', [ApiKeyController::class, 'test']);