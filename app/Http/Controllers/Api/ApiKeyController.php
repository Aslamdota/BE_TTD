<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\MstApi;
use App\Models\MstKeyApi;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class ApiKeyController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/keys/generate",
     *     tags={"API Management"},
     *     summary="Generate new API keys",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"api_id"},
     *             @OA\Property(property="api_id", type="integer")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="API keys generated"
     *     )
     * )
     */
    public function generateKeys(Request $request)
    {
        $request->validate([
            'api_id' => 'required|exists:mst_api,id'
        ]);

        $apiKey = Str::random(40);
        $apiSecret = Str::random(60);

        $key = MstKeyApi::create([
            'api_id' => $request->api_id,
            'api_key' => $apiKey,
            'api_secret' => hash('sha256', $apiSecret)
        ]);

        return response()->json([
            'message' => 'API keys generated successfully',
            'api_key' => $apiKey,
            'api_secret' => $apiSecret, // Hanya ditampilkan sekali
            'key_info' => $key
        ], 201);
    }
    /**
     * @OA\Get(
     *     path="/api/test",
     *     tags={"Test"},
     *     summary="Test endpoint for Swagger",
     *     @OA\Response(
     *         response=200,
     *         description="Success"
     *     )
     * )
     */
    public function test()
    {
        return response()->json(['message' => 'Swagger works!']);
    }
}
