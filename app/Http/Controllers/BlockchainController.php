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
     *             required={"document_hash", "signer", "timestamp"},
     *             @OA\Property(property="document_hash", type="string", example="0xe633e584a79873596fcfa93910aa87a1326a8cb1c5af9079e21a852aaa29cf8a"),
     *             @OA\Property(property="signer", type="string", example="0x1234567890abcdef1234567890abcdef12345678"),
     *             @OA\Property(property="timestamp", type="integer", example=1729932384)
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification result from blockchain",
     *         @OA\JsonContent(
     *             @OA\Property(property="is_valid", type="boolean", example=true),
     *             @OA\Property(property="timestamp", type="string", format="date-time"),
     *             @OA\Property(property="signer", type="string", example="0x1234567890abcdef1234567890abcdef12345678")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Blockchain error"
     *     )
     * )
     */
    public function verifyDocumentHash(Request $request)
    {
        $validated = $request->validate([
            'document_hash' => ['required', 'regex:/^0x[a-fA-F0-9]{64}$/'],
            'signer' => ['required', 'regex:/^0x[a-fA-F0-9]{40}$/'],
            'timestamp' => ['required', 'numeric'],
            'expires_at' => ['required', 'numeric']
        ]);

        $result = $this->blockchain->verifyDocumentHash(
            $validated['document_hash'],
            $validated['signer'],
            $validated['timestamp'],
            $validated['expires_at']
        );

        if ($result['success']) {
            return response()->json([
                'is_valid' => $result['is_valid'],
                'timestamp' => $result['timestamp'],
                'expires_at' => $result['expires_at'],
                'signer' => $result['signer'],
                'validation_details' => $result['validation_details'] ?? null
            ]);
        }

        return response()->json([
            'message' => 'Document verification error',
            'error' => $result['error']
        ], 500);
    }

    public function verifySignatureHash(Request $request)
    {
        $validated = $request->validate([
            'signature_hash' => ['required', 'regex:/^0x[a-fA-F0-9]{64}$/'],
            'signer' => ['required', 'regex:/^0x[a-fA-F0-9]{40}$/'],
            'timestamp' => ['required', 'numeric'],
            'expires_at' => ['required', 'numeric']
        ]);

        $result = $this->blockchain->verifySignatureHash(
            $validated['signature_hash'],
            $validated['signer'],
            $validated['timestamp'],
            $validated['expires_at']
        );

        if ($result['success']) {
            return response()->json([
                'is_valid' => $result['is_valid'],
                'timestamp' => $result['timestamp'],
                'expires_at' => $result['expires_at'],
                'signer' => $result['signer'],
                'validation_details' => $result['validation_details'] ?? null
            ]);
        }

        return response()->json([
            'message' => 'Signature verification error',
            'error' => $result['error']
        ], 500);
    }
}
