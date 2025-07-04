<?php

namespace App\Http\Controllers;

use App\Models\Signature;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class SignatureController extends Controller
{
    /**
     * @OA\Get(
     *     path="/api/signatures",
     *     tags={"Signature"},
     *     summary="List all signatures for current user",
     *     operationId="listSignatures",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of signatures",
     *         @OA\JsonContent(
     *             type="array",
     *             @OA\Items(ref="#/components/schemas/Signature")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */
    public function index(Request $request)
    {
        $user = $request->user();
        $signatures = Signature::with('document')
            ->where('user_id', $user->id)
            ->orderByDesc('created_at')
            ->get();

        return response()->json($signatures);
    }

    /**
     * @OA\Get(
     *     path="/api/signatures/{id}",
     *     tags={"Signature"},
     *     summary="Get signature detail",
     *     operationId="showSignature",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Signature ID",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Signature detail",
     *         @OA\JsonContent(ref="#/components/schemas/Signature")
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Signature not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Signature not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */
    public function show(Request $request, $id)
    {
        $user = $request->user();
        $signature = Signature::with('document')
            ->where('user_id', $user->id)
            ->find($id);

        if (!$signature) {
            return response()->json(['message' => 'Signature not found'], 404);
        }

        return response()->json($signature);
    }

    /**
     * @OA\Get(
     *     path="/api/signatures/{id}/download",
     *     tags={"Signature"},
     *     summary="Download signature image",
     *     operationId="downloadSignature",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Signature ID",
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Signature image file (PNG or JPG)"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Signature or file not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Signature or file not found")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */
    public function download(Request $request, $id)
    {
        $user = $request->user();
        $signature = Signature::where('user_id', $user->id)->find($id);

        if (!$signature || !$signature->image_path) {
            return response()->json(['message' => 'Signature or file not found'], 404);
        }

        $path = $signature->image_path;
        if (!Storage::disk('public')->exists($path)) {
            return response()->json(['message' => 'Signature file not found'], 404);
        }

        $file = Storage::disk('public')->get($path);
        $mime = Storage::disk('public')->mimeType($path);

        return response($file, 200)
            ->header('Content-Type', $mime)
            ->header('Content-Disposition', 'attachment; filename="signature_'.$signature->id.'.png"');
    }
}
