<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Models\AuditLog;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Str;

/**
 * @OA\Info(
 * title="VirSign API Documentation",
 * version="1.0"
 * )
 *
 * @OA\Server(
 * url="https://bettd-production.up.railway.app/",
 * description="Production API Server"
 * )
 */
class AuthController extends Controller
{
    // Constants for login attempt limiting
    const MAX_LOGIN_ATTEMPTS = 3;
    const BLOCK_DURATION_MINUTES = 30;

    /**
     * Register a new user
     *
     * @OA\Post(
     * path="/api/register",
     * tags={"Auth"},
     * summary="Register a new user",
     * operationId="register",
     * @OA\RequestBody(
     * required=true,
     * @OA\JsonContent(
     * required={"name","email","password"},
     * @OA\Property(property="name", type="string", example="John Doe"),
     * @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     * @OA\Property(property="password", type="string", format="password", example="password123"),
     * @OA\Property(property="nip", type="string", example="1234567890")
     * )
     * ),
     * @OA\Response(
     * response=201,
     * description="User registered successfully",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="User registered successfully"),
     * @OA\Property(property="user", type="object",
     * @OA\Property(property="id", type="integer", example=1),
     * @OA\Property(property="name", type="string", example="John Doe"),
     * @OA\Property(property="email", type="string", example="john@example.com"),
     * @OA\Property(property="nip", type="string", example="1234567890"),
     * @OA\Property(property="updated_at", type="string", format="date-time"),
     * @OA\Property(property="created_at", type="string", format="date-time")
     * )
     * )
     * ),
     * @OA\Response(
     * response=422,
     * description="Validation error",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="The given data was invalid."),
     * @OA\Property(property="errors", type="object")
     * )
     * )
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
            'is_login' => false,
            'failed_login_attempts' => 0,
            'blocked_until' => null
        ]);

        $user->generateKeyPair();
        $user->sendEmailVerificationNotification();

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user->makeHidden(['password', 'remember_token'])
        ], 201);
    }

    /**
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
     *             @OA\Property(property="force_logout", type="boolean", example=false, description="Set to true to force logout from other devices and login to this one.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="access_token", type="string", example="1|abcdefghijklmnopqrstuvwxyz"),
     *             @OA\Property(property="refresh_token", type="string", example="2|zyxwuvtsrqponmlkjihgfedcba"),
     *             @OA\Property(property="token_type", type="string", example="Bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600, description="Token expiration in seconds"),
     *             @OA\Property(property="user", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="john@example.com"),
     *                 @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="is_login", type="boolean", example=true),
     *                 @OA\Property(property="last_activity", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized / Invalid Credentials / Blocked",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Email atau password salah"),
     *             @OA\Property(property="code", type="string", example="AUTH_FAILED"),
     *             @OA\Property(property="remaining_attempts", type="integer", example=2, nullable=true, description="Remaining attempts before account is blocked"),
     *             @OA\Property(property="is_blocked", type="boolean", example=false, description="True if account is currently blocked"),
     *             @OA\Property(property="blocked_until", type="string", format="date-time", nullable=true, description="Timestamp when account block expires")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden / Already Logged In",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Anda sudah login di perangkat lain"),
     *             @OA\Property(property="code", type="string", example="ALREADY_LOGGED_IN"),
     *             @OA\Property(property="already_logged_in", type="boolean", example=true, description="True if user is already logged in on another device")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server Error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Terjadi kesalahan sistem"),
     *             @OA\Property(property="code", type="string", example="SERVER_ERROR")
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
                'force_logout' => 'sometimes|boolean'
            ]);

            $user = User::with('roles')->where('email', $credentials['email'])->first();
            $forceLogout = $credentials['force_logout'] ?? false;

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email atau password salah',
                    'code' => 'AUTH_FAILED'
                ], 401);
            }

            if ($user->blocked_until && Carbon::now()->lessThan($user->blocked_until)) {
                $remainingMinutes = ceil(Carbon::now()->diffInSeconds($user->blocked_until) / 60);

                return response()->json([
                    'status' => false,
                    'message' => 'Akun Anda terkunci sementara. Coba lagi dalam ' . $remainingMinutes . ' menit.',
                    'code' => 'ACCOUNT_BLOCKED',
                    'is_blocked' => true,
                    'blocked_until' => Carbon::parse($user->blocked_until)->toIso8601String(),
                    'remaining_minutes' => $remainingMinutes
                ], 403);
            }

            if ($user->is_login && !$forceLogout) {
                return response()->json([
                    'status' => false,
                    'message' => 'Anda sudah login di perangkat lain',
                    'already_logged_in' => true,
                    'code' => 'ALREADY_LOGGED_IN'
                ], 403);
            }

            if (!Auth::attempt($request->only('email', 'password'))) {
                $user->increment('failed_login_attempts');
                $remainingAttempts = self::MAX_LOGIN_ATTEMPTS - $user->failed_login_attempts;

                if ($user->failed_login_attempts >= self::MAX_LOGIN_ATTEMPTS) {
                    $user->blocked_until = Carbon::now()->addMinutes(self::BLOCK_DURATION_MINUTES);
                    $user->save();

                    return response()->json([
                        'status' => false,
                        'message' => 'Terlalu banyak percobaan login. Akun terkunci sementara. Coba lagi dalam ' . self::BLOCK_DURATION_MINUTES . ' menit.',
                        'code' => 'TOO_MANY_ATTEMPTS',
                        'is_blocked' => true,
                        'blocked_until' => $user->blocked_until->toIso8601String(),
                        'remaining_minutes' => self::BLOCK_DURATION_MINUTES
                    ], 401);
                }

                $user->save();

                return response()->json([
                    'status' => false,
                    'message' => 'Email atau password salah',
                    'code' => 'AUTH_FAILED',
                    'remaining_attempts' => max(0, $remainingAttempts)
                ], 401);
            }

            $user->failed_login_attempts = 0;
            $user->blocked_until = null;

            if ($forceLogout) {
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
                'expires_in' => config('sanctum.expiration') * 60,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $user->roles->pluck('name'),
                    'is_login' => true,
                    'last_activity' => $user->last_activity
                ]
            ]);
            AuditLog::create([
                'user_id' => $user->id,
                'action' => 'login',
                'description' => 'User logged in',
                'ip_address' => $request->ip()
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'status' => false,
                'message' => 'Validasi gagal',
                'code' => 'VALIDATION_ERROR',
                'errors' => $e->errors()
            ], 422);
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
     *     summary="Logout user and revoke current access token",
     *     operationId="logout",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Logout berhasil"),
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="logout_time", type="string", format="date-time", example="2023-04-08T14:30:00Z")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated (token invalid/missing)",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Token tidak valid atau tidak ditemukan"),
     *             @OA\Property(property="code", type="string", example="INVALID_TOKEN")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden (account blocked)",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Akun Anda terkunci sementara"),
     *             @OA\Property(property="code", type="string", example="ACCOUNT_BLOCKED"),
     *             @OA\Property(property="blocked_until", type="string", format="date-time", example="2023-04-08T15:00:00Z")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Internal server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Terjadi kesalahan saat logout"),
     *             @OA\Property(property="code", type="string", example="SERVER_ERROR"),
     *             @OA\Property(property="error_detail", type="string", example="Database connection failed", nullable=true)
     *         )
     *     ),
     *     @OA\Header(
     *         header="X-Request-ID",
     *         description="Unique request ID",
     *         @OA\Schema(type="string", example="550e8400-e29b-41d4-a716-446655440000")
     *     )
     * )
     */
    public function logout(Request $request)
    {
        try {
            $user = $request->user();
            $user->currentAccessToken()?->delete();
            $user->is_login = false;
            $user->save();

            // Audit log: logout
            AuditLog::create([
                'user_id' => $user->id,
                'action' => 'logout',
                'description' => 'User logged out',
                'ip_address' => $request->ip()
            ]);

            return response()->json([
                'status' => true,
                'message' => 'Logout berhasil'
            ]);
        } catch (\Exception $e) {
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
     * path="/api/user",
     * tags={"Auth"},
     * summary="Get authenticated user details",
     * operationId="getUser",
     * security={{"sanctum":{}}},
     * @OA\Response(
     * response=200,
     * description="User details",
     * @OA\JsonContent(
     * @OA\Property(property="id", type="integer", example=1),
     * @OA\Property(property="name", type="string", example="John Doe"),
     * @OA\Property(property="email", type="string", example="john@example.com"),
     * @OA\Property(property="nip", type="string", example="1234567890"),
     * @OA\Property(property="is_login", type="boolean", example=true),
     * @OA\Property(property="roles", type="array", @OA\Items(type="string"))
     * )
     * ),
     * @OA\Response(
     * response=401,
     * description="Unauthenticated",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="Unauthenticated")
     * )
     * )
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
     * path="/api/check-session",
     * tags={"Auth"},
     * summary="Check session validity",
     * operationId="checkSession",
     * security={{"sanctum":{}}},
     * @OA\Response(
     * response=200,
     * description="Session is valid",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=true),
     * @OA\Property(property="is_valid", type="boolean", example=true),
     * @OA\Property(property="user", type="object",
     * @OA\Property(property="id", type="integer", example=1),
     * @OA\Property(property="name", type="string", example="John Doe"),
     * @OA\Property(property="email", type="string", example="john@example.com"),
     * @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     * @OA\Property(property="is_login", type="boolean", example=true),
     * @OA\Property(property="last_activity", type="string", format="date-time")
     * )
     * )
     * ),
     * @OA\Response(
     * response=401,
     * description="Unauthenticated / Session invalid or expired",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=false),
     * @OA\Property(property="is_valid", type="boolean", example=false),
     * @OA\Property(property="message", type="string", example="Sesi tidak valid atau telah kadaluarsa"),
     * @OA\Property(property="code", type="string", example="SESSION_EXPIRED", nullable=true),
     * @OA\Property(property="is_blocked", type="boolean", example=false, nullable=true),
     * @OA\Property(property="blocked_until", type="string", format="date-time", nullable=true)
     * )
     * ),
     * @OA\Response(
     * response=500,
     * description="Server Error",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=false),
     * @OA\Property(property="is_valid", type="boolean", example=false),
     * @OA\Property(property="message", type="string", example="Terjadi kesalahan sistem saat memeriksa sesi")
     * )
     * )
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
                    'message' => 'Sesi tidak valid atau telah kadaluarsa',
                    'code' => 'SESSION_EXPIRED'
                ], 401);
            }

            if ($user->blocked_until && Carbon::now()->lessThan($user->blocked_until)) {
                return response()->json([
                    'status' => false,
                    'is_valid' => false,
                    'message' => 'Akun Anda terkunci sementara.',
                    'code' => 'ACCOUNT_BLOCKED',
                    'is_blocked' => true,
                    'blocked_until' => $user->blocked_until->toISOString()
                ], 401);
            }

            if (!$user->is_login) {
                Log::warning('User session not active (is_login flag is false)', ['user_id' => $user->id]);
                return response()->json([
                    'status' => false,
                    'is_valid' => false,
                    'message' => 'Sesi tidak aktif',
                    'code' => 'SESSION_INACTIVE'
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
     * path="/api/active-session",
     * tags={"Auth"},
     * summary="Get active session information",
     * operationId="activeSession",
     * security={{"sanctum":{}}},
     * @OA\Response(
     * response=200,
     * description="Active session information",
     * @OA\JsonContent(
     * @OA\Property(property="hasActiveSession", type="boolean", example=true),
     * @OA\Property(property="lastActivity", type="string", format="date-time", nullable=true),
     * @OA\Property(property="device", type="string", example="Mozilla/5.0 (Windows NT 10.0)"),
     * @OA\Property(property="ip", type="string", example="127.0.0.1"),
     * @OA\Property(property="location", type="string", example="Localhost"),
     * @OA\Property(property="sessionCreatedAt", type="string", format="date-time")
     * )
     * ),
     * @OA\Response(
     * response=401,
     * description="Unauthenticated",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="Unauthenticated")
     * )
     * )
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
        // In a real application, you'd use a geolocation service here
        return $ip === '127.0.0.1' ? 'Localhost' : 'Unknown';
    }

    /**
     * Force logout from all devices
     *
     * @OA\Post(
     * path="/api/force-logout",
     * tags={"Auth"},
     * summary="Force logout from all devices",
     * operationId="forceLogout",
     * security={{"sanctum":{}}},
     * @OA\Response(
     * response=200,
     * description="Logged out from all devices",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=true),
     * @OA\Property(property="message", type="string", example="Logout dari semua perangkat berhasil")
     * )
     * ),
     * @OA\Response(
     * response=401,
     * description="Unauthenticated",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="Unauthenticated")
     * )
     * ),
     * @OA\Response(
     * response=500,
     * description="Server Error",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=false),
     * @OA\Property(property="message", type="string", example="Terjadi kesalahan saat logout dari semua perangkat")
     * )
     * )
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

    /**
     * Refresh access token using refresh token
     *
     * @OA\Post(
     * path="/api/refresh-token",
     * tags={"Auth"},
     * summary="Refresh access token",
     * operationId="refreshToken",
     * security={{"sanctum":{}}},
     * @OA\RequestBody(
     * required=true,
     * @OA\JsonContent(
     * required={"refresh_token"},
     * @OA\Property(property="refresh_token", type="string", example="2|zyxwuvtsrqponmlkjihgfedcba")
     * )
     * ),
     * @OA\Response(
     * response=200,
     * description="Token refreshed successfully",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=true),
     * @OA\Property(property="access_token", type="string", example="1|newaccesstoken"),
     * @OA\Property(property="refresh_token", type="string", example="2|newrefreshtoken"),
     * @OA\Property(property="token_type", type="string", example="Bearer"),
     * @OA\Property(property="expires_in", type="integer", example=3600)
     * )
     * ),
     * @OA\Response(
     * response=401,
     * description="Unauthorized / Invalid Refresh Token",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=false),
     * @OA\Property(property="message", type="string", example="Refresh token tidak valid"),
     * @OA\Property(property="code", type="string", example="INVALID_REFRESH_TOKEN"),
     * @OA\Property(property="is_blocked", type="boolean", example=false, nullable=true),
     * @OA\Property(property="blocked_until", type="string", format="date-time", nullable=true)
     * )
     * ),
     * @OA\Response(
     * response=500,
     * description="Server Error",
     * @OA\JsonContent(
     * @OA\Property(property="status", type="boolean", example=false),
     * @OA\Property(property="message", type="string", example="Gagal memperbarui token")
     * )
     * )
     * )
     */
    public function refreshToken(Request $request)
    {
        try {
            $request->validate([
                'refresh_token' => 'required|string'
            ]);

            $user = $request->user();

            if (!$user) {
                return response()->json([
                    'status' => false,
                    'message' => 'Unauthenticated',
                    'code' => 'UNAUTHENTICATED'
                ], 401);
            }

            $refreshToken = $user->tokens()
                ->where('name', 'VirSign Refresh Token')
                ->where('token', hash('sha256', $request->refresh_token))
                ->whereJsonContains('abilities', 'refresh')
                ->first();

            if (!$refreshToken) {
                $user->tokens()->delete();
                $user->is_login = false;
                $user->save();

                return response()->json([
                    'status' => false,
                    'message' => 'Refresh token tidak valid atau telah digunakan',
                    'code' => 'INVALID_REFRESH_TOKEN'
                ], 401);
            }

            $user->currentAccessToken()?->delete();
            $refreshToken->delete();

            $accessToken = $user->createToken('VirSign Access Token')->plainTextToken;
            $newRefreshToken = $user->createToken('VirSign Refresh Token', ['refresh'])->plainTextToken;

            return response()->json([
                'status' => true,
                'access_token' => $accessToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'Bearer',
                'expires_in' => config('sanctum.expiration') * 60
            ]);

        } catch (ValidationException $e) {
            return response()->json([
                'status' => false,
                'message' => 'Validasi gagal',
                'code' => 'VALIDATION_ERROR',
                'errors' => $e->errors()
            ], 422);
        } catch (\Throwable $e) {
            Log::error('Token refresh failed', [
                'user_id' => $request->user()?->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return response()->json([
                'status' => false,
                'message' => 'Gagal memperbarui token',
                'code' => 'REFRESH_FAILED',
                'error_detail' => config('app.debug') ? $e->getMessage() : null
            ], 401);
        }
    }

    /**
     * @OA\Put(
     *     path="/api/admin/users/{userId}/password",
     *     tags={"Admin"},
     *     summary="Admin change user password",
     *     operationId="adminChangeUserPassword",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="userId",
     *         in="path",
     *         required=true,
     *         description="ID of the user",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"password"},
     *             @OA\Property(property="password", type="string", format="password", example="newpassword123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Password updated successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found"
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function adminChangeUserPassword(Request $request, $userId)
    {
        $request->validate([
            'password' => 'required|string|min:8'
        ]);
        $user = \App\Models\User::findOrFail($userId);
        $user->password = \Hash::make($request->password);
        $user->save();
    
        \App\Models\AuditLog::create([
            'user_id' => auth()->id(),
            'action' => 'admin_change_password',
            'description' => 'Admin changed password for user ID: '.$userId,
            'ip_address' => $request->ip()
        ]);
    
        return response()->json(['message' => 'Password updated successfully']);
    }


    public function forgotPassword(Request $request)
    {
        $request->validate(['email' => 'required|email']);
        $status = Password::sendResetLink($request->only('email'));
        return response()->json([
            'status' => $status === Password::RESET_LINK_SENT,
            'message' => __($status)
        ]);
    }

    public function resetPassword(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->save();

                event(new PasswordReset($user));
            }
        );

        return response()->json([
            'status' => $status === Password::PASSWORD_RESET,
            'message' => __($status)
        ]);
    }

    /**
     * @OA\Put(
     *     path="/api/user/profile",
     *     tags={"Auth"},
     *     summary="Update user profile",
     *     operationId="updateProfile",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Nama Baru"),
     *             @OA\Property(property="nip", type="string", example="1234567890")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Profil berhasil diupdate",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Profil berhasil diupdate"),
     *             @OA\Property(property="user", type="object")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function updateProfile(Request $request)
    {
        $user = $request->user();
        $request->validate([
            'name' => 'sometimes|string|max:255',
            'nip' => 'sometimes|string|max:50|unique:users,nip,'.$user->id,
        ]);
        $user->update($request->only('name', 'nip'));
        return response()->json(['status' => true, 'message' => 'Profil berhasil diupdate', 'user' => $user]);
    }
    
    /**
     * @OA\Post(
     *     path="/api/user/change-password",
     *     tags={"Auth"},
     *     summary="Change user password",
     *     operationId="changePassword",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"old_password","new_password","new_password_confirmation"},
     *             @OA\Property(property="old_password", type="string", format="password", example="oldpass"),
     *             @OA\Property(property="new_password", type="string", format="password", example="newpass123"),
     *             @OA\Property(property="new_password_confirmation", type="string", format="password", example="newpass123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password berhasil diganti",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Password berhasil diganti")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function changePassword(Request $request)
    {
        $user = $request->user();
        $request->validate([
            'old_password' => 'required',
            'new_password' => 'required|string|min:8|confirmed'
        ]);
        if (!\Hash::check($request->old_password, $user->password)) {
            return response()->json(['status' => false, 'message' => 'Password lama salah'], 422);
        }
        $user->password = \Hash::make($request->new_password);
        $user->save();
        return response()->json(['status' => true, 'message' => 'Password berhasil diganti']);
    }

    /**
     * @OA\Post(
     *     path="/api/send-otp",
     *     tags={"Auth"},
     *     summary="Send OTP to user email",
     *     operationId="sendOtp",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="OTP sent"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="User not found"
     *     )
     * )
     */
    public function sendOtp(Request $request)
    {
        $user = User::where('email', $request->email)->firstOrFail();
        $otp = rand(100000, 999999);
        $user->otp_code = $otp;
        $user->otp_expires_at = now()->addMinutes(10);
        $user->save();

        \Mail::raw("Kode OTP Anda: $otp", function ($msg) use ($user) {
            $msg->to($user->email)->subject('Kode OTP Login');
        });

        return response()->json(['message' => 'OTP sent']);
    }

    /**
     * @OA\Post(
     *     path="/api/verify-otp",
     *     tags={"Auth"},
     *     summary="Verify OTP code",
     *     operationId="verifyOtp",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","otp"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="otp", type="string", example="123456")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="OTP valid"
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="OTP tidak valid"
     *     )
     * )
     */
    public function verifyOtp(Request $request)
    {
        $user = User::where('email', $request->email)->firstOrFail();
        if ($user->otp_code === $request->otp && now()->lessThan($user->otp_expires_at)) {
            $user->otp_code = null;
            $user->otp_expires_at = null;
            $user->save();
            return response()->json(['status' => true, 'message' => 'OTP valid']);
        }
        return response()->json(['status' => false, 'message' => 'OTP tidak valid'], 422);
    }
}
