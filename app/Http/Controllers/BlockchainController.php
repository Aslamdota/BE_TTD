<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Web3\Web3;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Web3\Contract;

/**
 * @OA\Tag(
 *     name="Blockchain",
 *     description="Blockchain integration endpoints"
 * )
 */
class BlockchainController extends Controller
{
    /**
     * @OA\Post(
     *     path="/api/blockchain/store",
     *     tags={"Blockchain"},
     *     summary="Store document hash in blockchain",
     *     operationId="storeHashInBlockchain",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"document_hash","signature_hash"},
     *             @OA\Property(property="document_hash", type="string", example="a1b2c3..."),
     *             @OA\Property(property="signature_hash", type="string", example="x1y2z3...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Hash stored in blockchain",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Hash stored in blockchain"),
     *             @OA\Property(property="tx_hash", type="string", example="0x123..."),
     *             @OA\Property(property="document_hash", type="string", example="a1b2c3...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Blockchain error"
     *     )
     * )
     */
    public function storeHash(Request $request)
    {
        // Implementasi method storeHash seperti sebelumnya
    }

    /**
     * @OA\Post(
     *     path="/api/blockchain/verify",
     *     tags={"Blockchain"},
     *     summary="Verify document hash in blockchain",
     *     operationId="verifyHashInBlockchain",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"document_hash"},
     *             @OA\Property(property="document_hash", type="string", example="a1b2c3...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification result from blockchain",
     *         @OA\JsonContent(
     *             @OA\Property(property="is_valid", type="boolean", example=true),
     *             @OA\Property(property="timestamp", type="string", format="date-time"),
     *             @OA\Property(property="signer", type="string", example="0x123...")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Blockchain error"
     *     )
     * )
     */
    public function verifyHash(Request $request)
    {
        $request->validate([
            'document_hash' => 'required|string'
        ]);

        $documentHash = $request->document_hash;

        $this->contract->call('verifyHash', $documentHash, function ($err, $result) {
            if ($err !== null) {
                return response()->json(['error' => $err->getMessage()], 500);
            }

            return response()->json([
                'is_valid' => $result[0],
                'timestamp' => $result[1],
                'signer' => $result[2]
            ]);
        });
    }
}
