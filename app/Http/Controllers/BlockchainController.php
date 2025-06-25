<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\BlockchainService;

/**
 * @OA\Tag(
 *     name="Blockchain",
 *     description="Blockchain integration endpoints"
 * )
 */
class BlockchainController extends Controller
{
    protected $blockchain;

    public function __construct(BlockchainService $blockchain)
    {
        $this->blockchain = $blockchain;
    }

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
        $request->validate([
            'document_hash' => 'required|string',
            'signature_hash' => 'required|string'
        ]);

        $result = $this->blockchain->storeDocumentHash($request->document_hash, $request->signature_hash);

        if ($result['success']) {
            return response()->json([
                'message' => 'Hash stored in blockchain',
                'tx_hash' => $result['tx_hash'],
                'document_hash' => $request->document_hash
            ]);
        } else {
            return response()->json([
                'message' => 'Blockchain error',
                'error' => $result['error']
            ], 500);
        }
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

        $result = $this->blockchain->verifyDocumentHash($request->document_hash);

        if ($result['success']) {
            return response()->json([
                'is_valid' => $result['is_valid'],
                'timestamp' => $result['timestamp'],
                'signer' => $result['signer']
            ]);
        } else {
            return response()->json([
                'message' => 'Blockchain error',
                'error' => $result['error']
            ], 500);
        }
    }
}
