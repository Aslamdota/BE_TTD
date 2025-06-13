<?php

namespace App\Http\Controllers;

use App\Models\MstApi;
use App\Models\MstKeyApi;
use App\Models\MstMenu;
use App\Models\Role;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @OA\Tag(
 *     name="Admin",
 *     description="Admin management endpoints"
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
 */
class AdminController extends Controller
{
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
     *     @OA\Response(
     *         response=200,
     *         description="List of users",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="current_page", type="integer"),
     *             @OA\Property(property="data", type="array", @OA\Items(type="object")),
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
        // Implementasi method listUsers seperti sebelumnya
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
     *             @OA\Property(property="user", type="object")
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

    public function deleteUser($userId)
    {
        $user = User::findOrFail($userId);
        $user->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }

    // Role Management
    public function listRoles()
    {
        $roles = Role::all();
        return response()->json($roles);
    }

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

    // API Key Management
    public function listApis()
    {
        $apis = MstApi::with('keys')->get();
        return response()->json($apis);
    }

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

    public function revokeApiKey($keyId)
    {
        $key = MstKeyApi::findOrFail($keyId);
        $key->delete();

        return response()->json(['message' => 'API key revoked successfully']);
    }

    // Menu Management
    public function listMenus()
    {
        $menus = MstMenu::orderBy('position')->get();
        return response()->json($menus);
    }

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

    public function deleteMenu($menuId)
    {
        $menu = MstMenu::findOrFail($menuId);
        $menu->delete();

        return response()->json(['message' => 'Menu deleted successfully']);
    }
}
