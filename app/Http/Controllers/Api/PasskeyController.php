<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Passkey;
use Illuminate\Support\Facades\Auth;

class PasskeyController extends Controller
{
    /**
     * @OA\Get(
     *     path="/api/passkeys",
     *     tags={"Passkey"},
     *     summary="List all passkeys for current user",
     *     security={{"sanctum":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="List of passkeys",
     *         @OA\JsonContent(type="array", @OA\Items(
     *             @OA\Property(property="id", type="integer"),
     *             @OA\Property(property="public_key", type="string"),
     *             @OA\Property(property="status", type="string"),
     *             @OA\Property(property="created_at", type="string", format="date-time"),
     *             @OA\Property(property="revoked_at", type="string", format="date-time", nullable=true)
     *         ))
     *     )
     * )
     */
    public function index(Request $request)
    {
        $user = $request->user();
        $passkeys = $user->passkeys()->orderByDesc('created_at')->get(['id', 'public_key', 'status', 'created_at', 'revoked_at']);
        return response()->json($passkeys);
    }

    /**
     * @OA\Post(
     *     path="/api/passkeys",
     *     tags={"Passkey"},
     *     summary="Create new passkey (revoke old), with paraphrase",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"paraphrase"},
     *             @OA\Property(property="paraphrase", type="string", example="kata-rahasia-anda")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Passkey created",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Passkey created"),
     *             @OA\Property(property="passkey", type="object")
     *         )
     *     )
     * )
     */
    public function store(Request $request)
    {
        $user = $request->user();
        $request->validate([
            'paraphrase' => 'required|string|min:6|max:255'
        ]);

        // Revoke all old passkeys
        $user->passkeys()->where('status', 'active')->update([
            'status' => 'revoked',
            'revoked_at' => now()
        ]);

        // Generate new keypair
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $config['config'] = 'C:/Xampp/apache/conf/openssl.cnf';
        }
        $res = openssl_pkey_new($config);
        if (!$res) {
            return response()->json(['message' => 'Failed to generate keypair'], 500);
        }
        $privateKey = '';
        openssl_pkey_export($res, $privateKey, null, $config);
        $publicKeyDetails = openssl_pkey_get_details($res);
        $publicKey = $publicKeyDetails['key'];
        openssl_pkey_free($res);

        $passkey = Passkey::create([
            'user_id' => $user->id,
            'public_key' => $publicKey,
            'private_key' => $privateKey,
            'paraphrase' => bcrypt($request->paraphrase),
            'status' => 'active'
        ]);

        return response()->json([
            'message' => 'Passkey created',
            'passkey' => [
                'id' => $passkey->id,
                'public_key' => $passkey->public_key,
                'status' => $passkey->status,
                'created_at' => $passkey->created_at
            ]
        ], 201);
    }

    /**
     * @OA\Put(
     *     path="/api/passkeys/{id}/revoke",
     *     tags={"Passkey"},
     *     summary="Revoke a passkey",
     *     security={{"sanctum":{}}},
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Passkey revoked",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Passkey revoked")
     *         )
     *     ),
     *     @OA\Response(response=404, description="Not found")
     * )
     */
    public function revoke(Request $request, $id)
    {
        $user = $request->user();
        $passkey = $user->passkeys()->where('id', $id)->first();
        if (!$passkey) {
            return response()->json(['message' => 'Passkey not found'], 404);
        }
        $passkey->status = 'revoked';
        $passkey->revoked_at = now();
        $passkey->save();

        return response()->json(['message' => 'Passkey revoked']);
    }

    public function checkParaphase(Request $request)
    {
        $request->validate([
            'paraphrase' => 'required|string'
        ]);

        $passkey = $user->activePasskey();
        if (!$passkey) {
            return response()->json(['message' => 'No active passkey found'], 403);
        }

        if (!\Hash::check($request->paraphrase, $passkey->paraphrase)) {
            return response()->json(['message' => 'Paraphrase salah'], 403);
        }
    }
}
