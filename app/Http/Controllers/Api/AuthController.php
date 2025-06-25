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
use Illuminate\Support\Facades\DB;
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
                'force_logout' => 'sometimes|boolean'
            ]);

            $user = User::with('roles')->where('email', $credentials['email'])->first();

            if ($user && $user->is_login && !($credentials['force_logout'] ?? false)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Anda sudah login di perangkat lain',
                    'already_logged_in' => true,
                    'code' => 'ALREADY_LOGGED_IN'
                ], 403);
            }

            if (!Auth::attempt($request->only('email', 'password'))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email atau password salah',
                    'code' => 'AUTH_FAILED'
                ], 401);
            }

            $user = $request->user();

            if ($credentials['force_logout'] ?? false) {
                $user->tokens()->delete();
            } else {
                $user->currentAccessToken()?->delete();
            }

            $user->is_login = true;
            $user->last_activity = now();
            $user->save();

            $accessToken = $user->createToken('VirSign Access Token')->plainTextToken;
            $refreshToken = $user->createToken('VirSign Refresh Token', ['refresh'])->plainTextToken;

            return response()->json([
                'status' => true,
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
                'expires_in' => config('sanctum.expiration') * 60, // in seconds
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $user->roles->pluck('name'),
                    'is_login' => true,
                    'last_activity' => $user->last_activity
                ]
            ]);

        } catch (\Throwable $e) {
            Log::error('Login failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'ip' => $request->ip(),
                'email' => $request->email
            ]);

            return response()->json([
                'status' => false,
                'message' => 'Terjadi kesalahan sistem',
                'code' => 'SERVER_ERROR',
                'error_detail' => config('app.debug') ? $e->getMessage() : null
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
            try {
                DB::connection()->getPdo();
            } catch (\Exception $e) {
                Log::error('Database connection error in checkSession', ['error' => $e->getMessage()]);
                DB::reconnect();
                if (!DB::connection()->getPdo()) {
                    throw new \Exception('Failed to reconnect to database for session check');
                }
            }

            $user = $request->user();

            if (!$user) {
                Log::warning('Invalid session - no user found (token expired or invalid)');
                return response()->json([
                    'status' => false,
                    'is_valid' => false,
                    'message' => 'Sesi tidak valid atau telah kadaluarsa'
                ], 401);
            }

            if (!$user->is_login) {
                Log::warning('User session not active (is_login flag is false)', ['user_id' => $user->id]);
                return response()->json([
                    'status' => false,
                    'is_valid' => false,
                    'message' => 'Sesi tidak aktif'
                ], 401);
            }

            $user->last_activity = now();
            $user->save();

            return response()->json([
                'status' => true,
                'is_valid' => true,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $user->roles->pluck('name'),
                    'is_login' => $user->is_login,
                    'last_activity' => $user->last_activity
                ]
            ]);

        } catch (\Throwable $e) {
            Log::error('Session check failed due to system error', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent()
            ]);

            return response()->json([
                'status' => false,
                'is_valid' => false,
                'message' => 'Terjadi kesalahan sistem saat memeriksa sesi',
                'error_detail' => config('app.debug') ? $e->getMessage() : null
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

    public function refreshToken(Request $request)
    {
        try {
            $request->validate([
                'refresh_token' => 'required|string'
            ]);

            $refreshToken = $request->user()->tokens()
                ->where('token', hash('sha256', $request->refresh_token))
                ->where('abilities', '["refresh"]')
                ->first();

            if (!$refreshToken) {
                return response()->json([
                    'status' => false,
                    'message' => 'Refresh token tidak valid',
                    'code' => 'INVALID_REFRESH_TOKEN'
                ], 401);
            }

            $request->user()->currentAccessToken()?->delete();
            $refreshToken->delete();

            $accessToken = $request->user()->createToken('VirSign Access Token')->plainTextToken;
            $newRefreshToken = $request->user()->createToken('VirSign Refresh Token', ['refresh'])->plainTextToken;

            return response()->json([
                'status' => true,
                'access_token' => $accessToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'Bearer',
                'expires_in' => config('sanctum.expiration') * 60
            ]);

        } catch (\Throwable $e) {
            Log::error('Token refresh failed', [
                'user_id' => $request->user()?->id,
                'error' => $e->getMessage()
            ]);

            return response()->json([
                'status' => false,
                'message' => 'Gagal memperbarui token',
                'code' => 'REFRESH_FAILED'
            ], 401);
        }
    }
}
