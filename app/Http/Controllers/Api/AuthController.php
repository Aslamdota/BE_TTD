<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use Laravel\Sanctum\PersonalAccessToken;

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
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);

        $user = User::where('email', $credentials['email'])->first();

        if ($user && $user->is_login) {
            return response()->json([
                'message' => 'Anda sudah login di perangkat lain',
                'already_logged_in' => true
            ], 403);
        }

        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $user = $request->user();
        
        $user->tokens()->delete();
        
        $user->is_login = true;
        $user->save();

        $token = $user->createToken('Personal Access Token')->plainTextToken;
        $roles = $user->roles->pluck('name');

        return response()->json([
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
        $user = $request->user();
        $user->is_login = false;
        $user->save();
        
        $request->user()->currentAccessToken()->delete();
        
        return response()->json(['message' => 'Successfully logged out']);
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
     *     path="/api/auth/check-session",
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
        $user = $request->user();
        
        if (!$user) {
            return response()->json([
                'isValid' => false,
                'message' => 'Unauthenticated'
            ], 401);
        }

        $token = $user->currentAccessToken();
        if (!$token) {
            return response()->json([
                'isValid' => false,
                'message' => 'Token invalid'
            ], 401);
        }

        if (!$user->is_login) {
            $user->tokens()->where('id', $token->id)->delete();
            
            return response()->json([
                'isValid' => false,
                'message' => 'Session expired'
            ], 401);
        }

        return response()->json([
            'isValid' => true,
            'user' => $user->only(['id', 'name', 'email', 'roles']),
            'lastActivity' => $token->last_used_at
        ]);
    }

    /**
     * Get active session information
     * 
     * @OA\Get(
     *     path="/api/auth/active-session",
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
     *     path="/api/auth/force-logout",
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
        $user = $request->user();
        
        if (!$user) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        Log::info("Force logout initiated for user {$user->id} from IP: {$request->ip()}");

        $user->is_login = false;
        $user->save();
        
        $user->tokens()->delete();
        
        return response()->json(['message' => 'Logged out from all devices']);
     }
}