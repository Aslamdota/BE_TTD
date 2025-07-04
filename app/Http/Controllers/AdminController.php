<?php

namespace App\Http\Controllers;

use App\Models\MstApi;
use App\Models\MstKeyApi;
use App\Models\MstMenu;
use App\Models\Role;
use App\Models\User;
use App\Models\Certificate;
use App\Models\Document;
use App\Models\Signature;
use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use App\Imports\DosenImport;
use Maatwebsite\Excel\Facades\Excel;

/**
 * @OA\Tag(
 *     name="Admin",
 *     description="Admin management endpoints"
 * )
 *
 * @OA\Schema(
 *     schema="User",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="email", type="string"),
 *     @OA\Property(property="nip", type="string"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 *
 * @OA\Schema(
 *     schema="Role",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="description", type="string", nullable=true),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 *
 * @OA\Schema(
 *     schema="Api",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="status", type="boolean"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 *
 * @OA\Schema(
 *     schema="ApiKey",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="api_id", type="integer"),
 *     @OA\Property(property="api_key", type="string"),
 *     @OA\Property(property="api_secret", type="string"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 *
 * @OA\Schema(
 *     schema="Menu",
 *     @OA\Property(property="id", type="integer"),
 *     @OA\Property(property="name", type="string"),
 *     @OA\Property(property="description", type="string", nullable=true),
 *     @OA\Property(property="position", type="integer"),
 *     @OA\Property(property="status", type="boolean"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 */
class AdminController extends Controller
{
    /**
     * @OA\Get(
     *     path="/api/admin/dashboard",
     *     tags={"Admin"},
     *     summary="Get dashboard summary for admin",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Dashboard summary",
     *         @OA\JsonContent(
     *             @OA\Property(property="total_users", type="integer"),
     *             @OA\Property(property="total_documents", type="integer"),
     *             @OA\Property(property="total_signatures", type="integer"),
     *             @OA\Property(property="total_verified_documents", type="integer"),
     *             @OA\Property(property="bar_chart", type="array", @OA\Items(type="object")),
     *             @OA\Property(property="pie_chart", type="array", @OA\Items(type="object"))
     *         )
     *     )
     * )
     */
    public function dashboardSummary()
    {
        // Total
        $totalUsers = User::count();
        $totalDocuments = Document::count();
        $totalSignatures = Signature::where('status', 'signed')->count();
        $totalVerifiedDocuments = Document::where('hash_verified', true)->count();

        // Bar chart: aktivitas dokumen per hari 7 hari terakhir
        $barChart = AuditLog::select(DB::raw('DATE(created_at) as date'), DB::raw('count(*) as total'))
            ->where('action', 'like', '%document%')
            ->where('created_at', '>=', now()->subDays(7))
            ->groupBy('date')
            ->orderBy('date')
            ->get();

        // Pie chart: distribusi status dokumen
        $pieChart = Document::select('status', DB::raw('count(*) as total'))
            ->groupBy('status')
            ->get();

        return response()->json([
            'total_users' => $totalUsers,
            'total_documents' => $totalDocuments,
            'total_signatures' => $totalSignatures,
            'total_verified_documents' => $totalVerifiedDocuments,
            'bar_chart' => $barChart,
            'pie_chart' => $pieChart,
        ]);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/audit-logs",
     *     tags={"Admin"},
     *     summary="Get audit logs (activity history)",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         @OA\Schema(type="integer", default=10)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Audit logs",
     *         @OA\JsonContent(
     *             @OA\Property(property="current_page", type="integer"),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="user_id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="action", type="string", example="upload_document"),
     *                     @OA\Property(property="description", type="string", example="Upload dokumen: Contoh Dokumen"),
     *                     @OA\Property(property="ip_address", type="string", example="127.0.0.1"),
     *                     @OA\Property(property="created_at", type="string", format="date-time", example="2025-07-03T10:00:00Z")
     *                 )
     *             ),
     *             @OA\Property(property="first_page_url", type="string"),
     *             @OA\Property(property="from", type="integer"),
     *             @OA\Property(property="last_page", type="integer"),
     *             @OA\Property(property="last_page_url", type="string"),
     *             @OA\Property(property="next_page_url", type="string", nullable=true),
     *             @OA\Property(property="path", type="string"),
     *             @OA\Property(property="per_page", type="integer"),
     *             @OA\Property(property="prev_page_url", type="string", nullable=true),
     *             @OA\Property(property="to", type="integer"),
     *             @OA\Property(property="total", type="integer")
     *         )
     *     )
     * )
     */
    public function auditLogs(Request $request)
    {
        $logs = AuditLog::with('user')
            ->orderByDesc('created_at')
            ->paginate($request->per_page ?? 10);

        $logs->getCollection()->transform(function ($log) {
            return [
                'id' => $log->id,
                'user_id' => $log->user_id,
                'name' => $log->user ? $log->user->name : null,
                'action' => $log->action,
                'description' => $log->description,
                'ip_address' => $log->ip_address,
                'created_at' => $log->created_at,
            ];
        });

        return response()->json($logs);
    }

   /**
     * @OA\Get(
     *     path="/api/admin/users",
     *     tags={"Admin"},
     *     summary="List all users",
     *     operationId="listUsers",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page number",
     *         @OA\Schema(type="integer", default=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Items per page",
     *         @OA\Schema(type="integer", default=10)
     *     ),
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search keyword (by name, email, or nip)",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\Parameter(
     *         name="status",
     *         in="query",
     *         description="User active status: '1' for active, '0' for inactive",
     *         @OA\Schema(type="string", enum={"1", "0"})
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of users",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="current_page", type="integer"),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", example="john@example.com"),
     *                     @OA\Property(property="nip", type="string", example="1234567890"),
     *                     @OA\Property(property="is_active", type="boolean", example=true),
     *                     @OA\Property(property="roles", type="array", @OA\Items(type="string", example="admin")),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time")
     *                 )
     *             ),
     *             @OA\Property(property="first_page_url", type="string"),
     *             @OA\Property(property="from", type="integer"),
     *             @OA\Property(property="last_page", type="integer"),
     *             @OA\Property(property="last_page_url", type="string"),
     *             @OA\Property(property="links", type="array", @OA\Items(type="object")),
     *             @OA\Property(property="next_page_url", type="string", nullable=true),
     *             @OA\Property(property="path", type="string"),
     *             @OA\Property(property="per_page", type="integer"),
     *             @OA\Property(property="prev_page_url", type="string", nullable=true),
     *             @OA\Property(property="to", type="integer"),
     *             @OA\Property(property="total", type="integer")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     )
     * )
     */
    public function listUsers(Request $request)
    {
        $excludedEmails = ['developertua@iwu.local', 'developermuda@iwu.local'];

        $query = User::with('roles')
            ->whereNotIn('email', $excludedEmails);

        if ($search = $request->input('search')) {
            $query->where(function ($q) use ($search) {
                $q->where('name', 'like', "%$search%")
                ->orWhere('email', 'like', "%$search%")
                ->orWhere('nip', 'like', "%$search%");
            });
        }

        if ($request->filled('status')) {
            $status = $request->input('status');
            if (in_array($status, ['0', '1'], true)) {
                $query->where('is_active', $status);
            }
        }

        $users = $query->paginate($request->per_page ?? 10);

        $users->getCollection()->transform(function ($user) {
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'nip' => $user->nip,
                'is_active' => (bool) $user->is_active,
                'roles' => $user->roles->pluck('name'),
                'created_at' => $user->created_at,
                'updated_at' => $user->updated_at,
            ];
        });

        return response()->json($users);
    }


    /**
     * @OA\Put(
     *     path="/api/admin/users/{userId}/active",
     *     tags={"Admin"},
     *     summary="Set user active status (aktif/nonaktif)",
     *     operationId="setUserActiveStatus",
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
     *             required={"is_active"},
     *             @OA\Property(property="is_active", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User status updated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User status updated"),
     *             @OA\Property(property="is_active", type="boolean", example=true)
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
    public function setUserActiveStatus(Request $request, $userId)
    {
        $request->validate([
            'is_active' => 'required|boolean'
        ]);
        $user = User::findOrFail($userId);
        $user->is_active = $request->is_active;
        $user->save();

        return response()->json(['message' => 'User status updated', 'is_active' => $user->is_active]);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/users",
     *     tags={"Admin"},
     *     summary="Create a new user",
     *     operationId="createUser",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","password"},
     *             @OA\Property(property="name", type="string", example="John Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="password123"),
     *             @OA\Property(property="nip", type="string", example="1234567890"),
     *             @OA\Property(
     *                 property="roles",
     *                 type="array",
     *                 @OA\Items(type="integer", example=2),
     *                 description="Array of role IDs"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User created successfully"),
     *             @OA\Property(property="user", type="object", ref="#/components/schemas/User")
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
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function createUser(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8',
            'nip' => 'nullable|string|unique:users',
            'roles' => 'array',
            'roles.*' => 'exists:roles,id'
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'nip' => $request->nip,
            'password' => Hash::make($request->password)
        ]);

        $user->generateKeyPair();

        if ($request->roles) {
            $user->roles()->sync($request->roles);
        }

        return response()->json(['message' => 'User created successfully', 'user' => $user]);
    }

    /**
     * @OA\Put(
     *     path="/api/admin/users/{userId}",
     *     tags={"Admin"},
     *     summary="Update a user",
     *     operationId="updateUser",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="userId",
     *         in="path",
     *         required=true,
     *         description="ID of the user to update",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Updated Name"),
     *             @OA\Property(property="email", type="string", format="email", example="updated@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="newpassword123"),
     *             @OA\Property(property="nip", type="string", example="9876543210"),
     *             @OA\Property(
     *                 property="roles",
     *                 type="array",
     *                 @OA\Items(type="integer", example=3),
     *                 description="Array of role IDs"
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User updated successfully"),
     *             @OA\Property(property="user", type="object", ref="#/components/schemas/User")
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
    public function updateUser(Request $request, $userId)
    {
        $request->validate([
            'name' => 'string',
            'email' => 'email|unique:users,email,' . $userId,
            'password' => 'nullable|string|min:8',
            'nip' => 'nullable|string|unique:users,nip,' . $userId,
            'roles' => 'array',
            'roles.*' => 'exists:roles,id'
        ]);

        $user = User::findOrFail($userId);

        $updateData = [
            'name' => $request->name ?? $user->name,
            'email' => $request->email ?? $user->email,
            'nip' => $request->nip ?? $user->nip,
        ];

        if ($request->password) {
            $updateData['password'] = Hash::make($request->password);
        }

        $user->update($updateData);

        if ($request->roles) {
            $user->roles()->sync($request->roles);
        }

        return response()->json(['message' => 'User updated successfully', 'user' => $user]);
    }

    /**
     * @OA\Delete(
     *     path="/api/admin/users/{userId}",
     *     tags={"Admin"},
     *     summary="Delete a user",
     *     operationId="deleteUser",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="userId",
     *         in="path",
     *         required=true,
     *         description="ID of the user to delete",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="User deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User deleted successfully")
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
     *     )
     * )
     */
    public function deleteUser($userId)
    {
        $user = User::with('roles')->findOrFail($userId);

        if ($user->roles->contains('name', 'admin')) {
            return response()->json([
                'message' => 'User dengan role admin tidak dapat dihapus.'
            ], 403);
        }

        $user->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/roles",
     *     tags={"Admin"},
     *     summary="List all roles",
     *     operationId="listRoles",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of roles",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/Role")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     )
     * )
     */
    public function listRoles()
    {
        $roles = Role::all();
        return response()->json($roles);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/roles",
     *     tags={"Admin"},
     *     summary="Create a new role",
     *     operationId="createRole",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(property="name", type="string", example="Editor"),
     *             @OA\Property(property="description", type="string", example="Can edit content")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Role created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Role created successfully"),
     *             @OA\Property(property="role", type="object", ref="#/components/schemas/Role")
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
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function createRole(Request $request)
    {
        $request->validate([
            'name' => 'required|string|unique:roles',
            'description' => 'nullable|string'
        ]);

        $role = Role::create([
            'name' => $request->name,
            'description' => $request->description
        ]);

        return response()->json(['message' => 'Role created successfully', 'role' => $role]);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/apis",
     *     tags={"Admin"},
     *     summary="List all APIs",
     *     operationId="listApis",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of APIs",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/Api")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     )
     * )
     */
    public function listApis()
    {
        $apis = MstApi::with('keys')->get();
        return response()->json($apis);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/apis",
     *     tags={"Admin"},
     *     summary="Create a new API",
     *     operationId="createApi",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(property="name", type="string", example="Payment API"),
     *             @OA\Property(property="status", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="API created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="API created successfully"),
     *             @OA\Property(property="api", type="object", ref="#/components/schemas/Api")
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
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function createApi(Request $request)
    {
        $request->validate([
            'name' => 'required|string|unique:mst_api',
            'status' => 'boolean'
        ]);

        $api = MstApi::create([
            'name' => $request->name,
            'status' => $request->status ?? true
        ]);

        return response()->json(['message' => 'API created successfully', 'api' => $api]);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/apis/{apiId}/keys",
     *     tags={"Admin"},
     *     summary="Generate API key",
     *     operationId="generateApiKey",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="apiId",
     *         in="path",
     *         required=true,
     *         description="ID of the API",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="API key generated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="API key generated successfully"),
     *             @OA\Property(property="key", type="object", ref="#/components/schemas/ApiKey")
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
     *         description="API not found"
     *     )
     * )
     */
    public function generateApiKey(Request $request, $apiId)
    {
        $api = MstApi::findOrFail($apiId);

        $key = MstKeyApi::create([
            'api_id' => $api->id,
            'api_key' => Str::uuid(),
            'api_secret' => Str::random(40)
        ]);

        return response()->json([
            'message' => 'API key generated successfully',
            'key' => $key
        ]);
    }

    /**
     * @OA\Delete(
     *     path="/api/admin/keys/{keyId}",
     *     tags={"Admin"},
     *     summary="Revoke API key",
     *     operationId="revokeApiKey",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="keyId",
     *         in="path",
     *         required=true,
     *         description="ID of the API key to revoke",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="API key revoked successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="API key revoked successfully")
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
     *         description="API key not found"
     *     )
     * )
     */
    public function revokeApiKey($keyId)
    {
        $key = MstKeyApi::findOrFail($keyId);
        $key->delete();

        return response()->json(['message' => 'API key revoked successfully']);
    }

    /**
     * @OA\Get(
     *     path="/api/admin/menus",
     *     tags={"Admin"},
     *     summary="List all menus",
     *     operationId="listMenus",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of menus",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/Menu")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     )
     * )
     */
    public function listMenus()
    {
        $menus = MstMenu::orderBy('position')->get();
        return response()->json($menus);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/menus",
     *     tags={"Admin"},
     *     summary="Create a new menu",
     *     operationId="createMenu",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(property="name", type="string", example="Dashboard"),
     *             @OA\Property(property="description", type="string", example="Main dashboard menu"),
     *             @OA\Property(property="position", type="integer", example=1),
     *             @OA\Property(property="status", type="boolean", example=true)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Menu created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Menu created successfully"),
     *             @OA\Property(property="menu", type="object", ref="#/components/schemas/Menu")
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
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function createMenu(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'description' => 'nullable|string',
            'position' => 'integer',
            'status' => 'boolean'
        ]);

        $menu = MstMenu::create([
            'name' => $request->name,
            'description' => $request->description,
            'position' => $request->position ?? 0,
            'status' => $request->status ?? true
        ]);

        return response()->json(['message' => 'Menu created successfully', 'menu' => $menu]);
    }

    /**
     * @OA\Put(
     *     path="/api/admin/menus/{menuId}",
     *     tags={"Admin"},
     *     summary="Update a menu",
     *     operationId="updateMenu",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="menuId",
     *         in="path",
     *         required=true,
     *         description="ID of the menu to update",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Updated Menu"),
     *             @OA\Property(property="description", type="string", example="Updated description"),
     *             @OA\Property(property="position", type="integer", example=2),
     *             @OA\Property(property="status", type="boolean", example=false)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Menu updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Menu updated successfully"),
     *             @OA\Property(property="menu", type="object", ref="#/components/schemas/Menu")
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
     *         description="Menu not found"
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */
    public function updateMenu(Request $request, $menuId)
    {
        $request->validate([
            'name' => 'string',
            'description' => 'nullable|string',
            'position' => 'integer',
            'status' => 'boolean'
        ]);

        $menu = MstMenu::findOrFail($menuId);
        $menu->update($request->all());

        return response()->json(['message' => 'Menu updated successfully', 'menu' => $menu]);
    }

    /**
     * @OA\Delete(
     *     path="/api/admin/menus/{menuId}",
     *     tags={"Admin"},
     *     summary="Delete a menu",
     *     operationId="deleteMenu",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="menuId",
     *         in="path",
     *         required=true,
     *         description="ID of the menu to delete",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Menu deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Menu deleted successfully")
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
     *         description="Menu not found"
     *     )
     * )
     */
    public function deleteMenu($menuId)
    {
        $menu = MstMenu::findOrFail($menuId);
        $menu->delete();

        return response()->json(['message' => 'Menu deleted successfully']);
    }

    /**
     * @OA\Post(
     *     path="/api/admin/import-dosen",
     *     tags={"Admin"},
     *     summary="Import dosen via Excel",
     *     operationId="importDosen",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"file"},
     *                 @OA\Property(
     *                     property="file",
     *                     type="string",
     *                     format="binary",
     *                     description="File Excel (.xlsx/.xls) dengan kolom: name, email, nip, password"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Import dosen berhasil",
     *         @OA\JsonContent(@OA\Property(property="message", type="string"))
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Import gagal"
     *     )
     * )
     */
    public function importDosen(Request $request)
    {
        $request->validate([
            'file' => 'required|file|mimes:xlsx,xls'
        ]);

        try {
            Excel::import(new DosenImport, $request->file('file'));
            return response()->json(['message' => 'Import dosen berhasil'], 200);
        } catch (Exception $e) {
            return response()->json(['message' => 'Import gagal', 'error' => $e->getMessage()], 500);
        }
    }

    public function listCertificates()
    {
        return response()->json(Certificate::with('user')->get());
    }

    public function createCertificate(Request $request)
    {
        $request->validate([
            'user_id' => 'required|exists:users,id',
            'serial_number' => 'required|unique:certificates,serial_number',
            'issuer' => 'required|string',
            'valid_from' => 'required|date',
            'valid_to' => 'required|date|after:valid_from',
        ]);
        $cert = Certificate::create($request->all());
        return response()->json(['message' => 'Certificate created', 'certificate' => $cert], 201);
    }
}
