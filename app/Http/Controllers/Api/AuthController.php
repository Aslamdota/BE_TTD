<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
/**
 * @OA\Info(
 *     title="VirSign API Documentation",
 *     version="1.0"
 * )
 *
 * @OA\Server(
 *     url="https://bettd-production.up.railway.app/",
 *     description="Production API Server"
 * )
 */
class AuthController extends Controller
{
    /**
     * Register a new user
     * 
     * @OA\Post(
     *     path="/api/register",
     *     tags={"Auth"},
     *     summary="Register a new user",
     *     operationId="register",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","password"},
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(property="nip", type="string", example="1234567890")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User registered successfully"),
     *             @OA\Property(property="user", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="john@example.com"),
     *                 @OA\Property(property="nip", type="string", example="1234567890"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time"),
     *                 @OA\Property(property="created_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users|max:255',
            'password' => 'required|string|min:8|confirmed',
            'nip' => 'nullable|string|unique:users|max:50'
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'nip' => $request->nip,
            'password' => Hash::make($request->password),
            'is_login' => false
        ]);

        $user->generateKeyPair();

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user->makeHidden(['password', 'remember_token'])
        ], 201);
    }

    /**
     * Authenticate user and create token
     * 
     * @OA\Post(
     *     path="/api/login",
     *     tags={"Auth"},
     *     summary="Login user",
     *     operationId="login",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(property="remember_me", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="access_token", type="string", example="1|abcdefghijklmnopqrstuvwxyz"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *             @OA\Property(property="user", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="john@example.com"),
     *                 @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="is_login", type="boolean", example=true)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        try {
            $credentials = $request->validate([
                'email' => 'required|email',
                'password' => 'required|string',
                'remember_me' => 'sometimes|boolean',
                'force_logout' => 'sometimes|boolean' // New parameter for force logout
            ]);

            $user = User::with('roles')->where('email', $credentials['email'])->first();

            if ($user && $user->is_login && !($credentials['force_logout'] ?? false)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Anda sudah login di perangkat lain',
                    'already_logged_in' => true,
                    'remaining_attempts' => null,
                    'is_blocked' => false
                ], 403);
            }

            // Attempt authentication
            if (!Auth::attempt($request->only('email', 'password'))) {
                throw ValidationException::withMessages([
                    'email' => [__('auth.failed')],
                ]);
            }

            $user = $request->user();
            if ($credentials['force_logout'] ?? false) {
                $user->tokens()->delete();
            } else {
                $user->currentAccessToken()?->delete();
            }

            $user->is_login = true;
            $user->save();

            $token = $user->createToken('VirSign Access Token')->plainTextToken;
            $roles = $user->roles->pluck('name');

            return response()->json([
                'status' => true,
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $roles,
                    'is_login' => $user->is_login,
                ]
            ]);

        } catch (ValidationException $e) {
            Log::warning('Login validation failed', ['error' => $e->errors()]);
            return response()->json([
                'status' => false,
                'message' => 'Validasi gagal',
                'errors' => $e->errors(),
                'already_logged_in' => false,
                'is_blocked' => false
            ], 422);
        } catch (\Exception $e) {
            Log::error('Login failed', ['error' => $e->getMessage()]);
            return response()->json([
                'status' => false,
                'message' => 'Terjadi kesalahan saat login',
                'already_logged_in' => false,
                'is_blocked' => false
            ], 500);
        }
    }
    /**
     * Logout user (revoke token)
     * 
     * @OA\Post(
     *     path="/api/logout",
     *     tags={"Auth"},
     *     summary="Logout user",
     *     operationId="logout",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function logout(Request $request)
    {
        try {
            $user = $request->user();
            
            if ($user) {
                $user->currentAccessToken()?->delete();
                $user->is_login = false;
                $user->save();
            }

            return response()->json([
                'status' => true,
                'message' => 'Logout berhasil'
            ]);

        } catch (\Exception $e) {
            Log::error('Logout failed', ['error' => $e->getMessage()]);
            return response()->json([
                'status' => false,
                'message' => 'Terjadi kesalahan saat logout'
            ], 500);
        }
    }

    /**
     * Get authenticated user details
     * 
     * @OA\Get(
     *     path="/api/user",
     *     tags={"Auth"},
     *     summary="Get authenticated user details",
     *     operationId="getUser",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="User details",
     *         @OA\JsonContent(
     *             @OA\Property(property="id", type="integer", example=1),
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", example="john@example.com"),
     *             @OA\Property(property="nip", type="string", example="1234567890"),
     *             @OA\Property(property="is_login", type="boolean", example=true),
     *             @OA\Property(property="roles", type="array", @OA\Items(type="string"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function user(Request $request)
    {
        $user = $request->user()->load('roles');
        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'nip' => $user->nip,
            'is_login' => $user->is_login,
            'roles' => $user->getRoleNames()
        ]);
    }

    /**
     * Check session validity
     * 
     * @OA\Get(
     *     path="/api/check-session",
     *     tags={"Auth"},
     *     summary="Check session validity",
     *     operationId="checkSession",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Session is valid",
     *         @OA\JsonContent(
     *             @OA\Property(property="isValid", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="isValid", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Session expired")
     *         )
     *     )
     * )
     */
    public function checkSession(Request $request)
    {
        try {
            $user = $request->user();
            
            if (!$user) {
                return response()->json([
                    'status' => false,
                    'is_valid' => false,
                    'message' => 'Sesi tidak valid'
                ], 401);
            }

            return response()->json([
                'status' => true,
                'is_valid' => true,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $user->roles->pluck('name'),
                    'is_login' => $user->is_login,
                ]
            ]);

        } catch (\Exception $e) {
            Log::error('Session check failed', ['error' => $e->getMessage()]);
            return response()->json([
                'status' => false,
                'is_valid' => false,
                'message' => 'Terjadi kesalahan saat memeriksa sesi'
            ], 500);
        }
    }

    /**
     * Get active session information
     * 
     * @OA\Get(
     *     path="/api/active-session",
     *     tags={"Auth"},
     *     summary="Get active session information",
     *     operationId="activeSession",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Active session information",
     *         @OA\JsonContent(
     *             @OA\Property(property="hasActiveSession", type="boolean", example=true),
     *             @OA\Property(property="lastActivity", type="string", format="date-time", nullable=true),
     *             @OA\Property(property="device", type="string", example="Mozilla/5.0 (Windows NT 10.0)"),
     *             @OA\Property(property="ip", type="string", example="127.0.0.1")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function activeSession(Request $request)
    {
        $user = $request->user();
        
        if (!$user) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $token = $user->currentAccessToken();
        $lastUsed = $token->last_used_at ? Carbon::parse($token->last_used_at) : null;

        return response()->json([
            'hasActiveSession' => $user->is_login,
            'lastActivity' => $lastUsed,
            'device' => $request->userAgent(),
            'ip' => $request->ip(),
            'location' => $this->getLocationFromIp($request->ip()),
            'sessionCreatedAt' => $token->created_at
        ]);
    }

    protected function getLocationFromIp($ip)
    {
        // In production, you might want to use a proper IP geolocation service
        return $ip === '127.0.0.1' ? 'Localhost' : 'Unknown';
    }

    /**
     * Force logout from all devices
     * 
     * @OA\Post(
     *     path="/api/force-logout",
     *     tags={"Auth"},
     *     summary="Force logout from all devices",
     *     operationId="forceLogout",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Logged out from all devices",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Logged out from all devices")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated")
     *         )
     *     )
     * )
     */
    public function forceLogout(Request $request)
    {
        try {
            $user = $request->user();
            
            if ($user) {
                $user->tokens()->delete();
                $user->is_login = false;
                $user->save();
            }

            return response()->json([
                'status' => true,
                'message' => 'Logout dari semua perangkat berhasil'
            ]);

        } catch (\Exception $e) {
            Log::error('Force logout failed', ['error' => $e->getMessage()]);
            return response()->json([
                'status' => false,
                'message' => 'Terjadi kesalahan saat logout dari semua perangkat'
            ], 500);
        }
    }
}