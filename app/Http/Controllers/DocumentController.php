<?php

namespace App\Http\Controllers;

use App\Models\Document;
use App\Models\MultiSignature;
use App\Models\Signature;
use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Models\BlockchainHash;
/**
 * @OA\Tag(
 *     name="Documents",
 *     description="Document management endpoints"
 * )
 *
 * @OA\Schema(
 *     schema="Document",
 *     required={"title","file_path","hash","creator_id"},
 *     @OA\Property(property="id", type="integer", example=1),
 *     @OA\Property(property="title", type="string", example="Contoh Dokumen"),
 *     @OA\Property(property="file_path", type="string", example="documents/abc123.pdf"),
 *     @OA\Property(property="hash", type="string", example="a1b2c3..."),
 *     @OA\Property(property="blockchain_tx", type="string", nullable=true),
 *     @OA\Property(property="creator_id", type="integer", example=1),
 *     @OA\Property(property="status", type="string", example="pending"),
 *     @OA\Property(property="created_at", type="string", format="date-time"),
 *     @OA\Property(property="updated_at", type="string", format="date-time")
 * )
 */
class DocumentController extends Controller
{
   /**
     * @OA\Post(
     *     path="/api/documents/upload",
     *     tags={"Documents"},
     *     summary="Upload a new signed document",
     *     operationId="uploadDocument",
     *     security={{"sanctum":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"title", "file"},
     *                 @OA\Property(property="title", type="string", example="Contoh Dokumen"),
     *                 @OA\Property(
     *                     property="file",
     *                     type="string",
     *                     format="binary",
     *                     description="File dokumen (PDF, maksimal 25MB)"
     *                 ),
     *                 @OA\Property(
     *                     property="hash",
     *                     type="string",
     *                     description="Hash SHA-256 dokumen dari frontend",
     *                     example="945e3f52aaa1bffee8f84039fd7e0ae9e351d952077c2c456451eaf25e6e1c65"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Document uploaded successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Document uploaded successfully"),
     *             @OA\Property(property="document", ref="#/components/schemas/Document")
     *         )
     *     ),
     *     @OA\Response(response=422, description="Validation error"),
     *     @OA\Response(response=401, description="Unauthorized")
     * )
     */
    public function upload(Request $request)
    {
        $request->validate([
            'title' => 'required|string|max:255',
            'file' => 'required|file|mimes:pdf|max:25600',
            'hash' => 'nullable|string',
            'tx_hash' => 'nullable|string'
        ]);

        $user = $request->user();
        $file = $request->file('file');

        // Simpan file
        $uniqueName = time() . '_' . $user->id . '_' . \Str::random(8) . '.pdf';
        $filePath = $file->storeAs('documents', $uniqueName, 'public');

        // Simpan dokumen ke database
        $document = Document::create([
            'title' => $request->title,
            'file_path' => $filePath,
            'creator_id' => $user->id,
            'status' => 'draft',
            'hash' => $request->input('hash')
        ]);

        // Catat log audit
        AuditLog::create([
            'user_id' => $user->id,
            'action' => 'upload_document',
            'description' => 'Upload dokumen: ' . $document->title,
            'ip_address' => $request->ip()
        ]);

        $blockchain = null;

        if ($request->filled('hash')) {
            $blockchain = $this->storeBlockchainHash([
                'hash' => $request->input('hash'),
                'type' => 'document_original',
                'user_id' => $user->id,
                'document_id' => $document->id,
                'blockchain_tx' => $request->input('tx_hash'),
                'signed_at' => now(),
            ]);
        }

        return response()->json([
            'message' => 'Document uploaded successfully',
            'document' => $document,
            'blockchain' => $blockchain,
        ], 201);

    }


    /**
         * @OA\Post(
         *     path="/api/documents/{documentId}/sign",
         *     tags={"Documents"},
         *     summary="Sign a document",
         *     operationId="signDocument",
         *     security={{"sanctum":{}}},
         *     @OA\Parameter(
         *         name="documentId",
         *         in="path",
         *         required=true,
         *         @OA\Schema(type="integer")
         *     ),
         *     @OA\RequestBody(
         *         required=true,
         *         @OA\JsonContent(
         *             required={"signature_hash"},
         *             @OA\Property(
         *                 property="signature_hash",
         *                 type="string",
         *                 example="e0b153f8883c47cf99d15bdc..."
         *             )
         *         )
         *     ),
         *     @OA\Response(
         *         response=200,
         *         description="Document signed successfully",
         *         @OA\JsonContent(
         *             @OA\Property(property="message", type="string", example="Document signed successfully"),
         *             @OA\Property(property="signature", ref="#/components/schemas/Signature")
         *         )
         *     ),
         *     @OA\Response(response=422, description="Validation error"),
         *     @OA\Response(response=401, description="Unauthorized"),
         *     @OA\Response(response=404, description="Document not found")
         * )
         */
    public function sign(Request $request, $documentId)
    {
        $request->validate([
            'signature_hash' => 'required|string|max:255',
            'signature_image' => 'nullable|image|mimes:png|max:2048',
            'name' => 'nullable|string|max:255',
            'tx_hash' => 'nullable|string'
        ]);

        $user = $request->user();
        $document = Document::findOrFail($documentId);

        // Upload gambar tanda tangan (jika ada)
        $path = null;
        if ($request->hasFile('signature_image')) {
            $path = $request->file('signature_image')->store("signatures/{$user->id}", 'public');
        }

        // Simpan ke tabel signatures
        $signature = Signature::create([
            'document_id' => $document->id,
            'user_id' => $user->id,
            'name' => $request->input('name'),
            'signature_hash' => $request->input('signature_hash'),
            'image_path' => $path,
            'signed_at' => now(),
            'status' => 'signed'
        ]);

        // Catat ke audit log
        AuditLog::create([
            'user_id' => $user->id,
            'action' => 'sign_document',
            'description' => 'Sign document: ' . $document->title,
            'ip_address' => $request->ip()
        ]);

        $blockchain = null;

        if ($request->filled('signature_hash')) {
            $blockchain = $this->storeBlockchainHash([
                'hash' => $request->input('signature_hash'),
                'type' => 'signature',
                'user_id' => $user->id,
                'document_id' => $document->id,
                'blockchain_tx' => $request->input('tx_hash'),
                'signed_at' => now(),
            ]);
        }

        return response()->json([
            'message' => 'Document signed successfully',
            'signature' => $signature,
            'blockchain' => $blockchain, 
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/verify",
     *     tags={"Documents"},
     *     summary="Verify document authenticity",
     *     operationId="verifyDocument",
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
     *                     description="File dokumen untuk diverifikasi"
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Verification result",
     *         @OA\JsonContent(
     *             @OA\Property(property="is_valid", type="boolean", example=true),
     *             @OA\Property(property="document", ref="#/components/schemas/Document"),
     *             @OA\Property(property="signatures", type="array", @OA\Items(type="object"))
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Document not found or has been modified"
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */

    public function verify(Request $request)
    {
        $request->validate(['hash' => 'required|string']);
        $document = Document::where('hash', $request->hash)->first();
        if (!$document) {
            return response()->json(['is_valid' => false, 'message' => 'Dokumen tidak ditemukan'], 404);
        }
        // Cek integritas, signature, dsb...
        return response()->json(['is_valid' => true, 'document' => $document]);
    }

    /**
     * @OA\Get(
     *     path="/api/documents",
     *     tags={"Documents"},
     *     summary="Get list of user's documents",
     *     operationId="listDocuments",
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
     *         description="List of documents",
     *         @OA\JsonContent(
     *             @OA\Property(property="current_page", type="integer"),
     *             @OA\Property(property="data", type="array", @OA\Items(ref="#/components/schemas/Document")),
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
     *     )
     * )
     */
    public function list(Request $request)
    {
        // Implementasi method list seperti sebelumnya
    }

    /**
     * @OA\Get(
     *     path="/api/documents/pending",
     *     tags={"Documents"},
     *     summary="Get list of pending signatures",
     *     operationId="pendingSignatures",
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
     *         description="List of pending signatures",
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
     *     )
     * )
     */
    public function pendingSignatures(Request $request)
    {
        $signatures = Signature::with('document.creator')
            ->where('user_id', $request->user()->id)
            ->where('status', 'pending')
            ->orderBy('created_at', 'desc')
            ->paginate(10);

        return response()->json($signatures);
    }

    public function saveSignatureTemplate($imageBase64)
    {
        $path = 'signatures/'.$this->id.'_template.png';
        \Storage::put($path, base64_decode($imageBase64));
        // Simpan path di kolom user jika perlu
        $this->signature_template = $path;
        $this->save();
    }

    public function getMySignatures(Request $request)
    {
        $user = $request->user();

        $signatures = Signature::with('document')
            ->where('user_id', $user->id)
            ->orderByDesc('signed_at')
            ->get()
            ->map(function ($signature) {
                $blockchain = BlockchainHash::where('hash', $signature->signature_hash)->first();
                
                $blockchainTx = $blockchain ? $blockchain->blockchain_tx : null;

                return [
                    'id' => $signature->id,
                    'name' => $signature->name,
                    'document_title' => optional($signature->document)->title,
                    'signature_hash' => $signature->signature_hash,
                    'image_url' => $signature->image_path 
                        ? secure_asset('storage/' . $signature->image_path) 
                        : null,
                    'image_path' => $signature->image_path,
                    'signed_at' => $signature->signed_at,
                    'status' => $signature->status,
                    'blockchain_tx' => $blockchainTx,
                ];
            });

        return response()->json([
            'signatures' => $signatures
        ]);
    }


    private function storeBlockchainHash(array $data)
    {
        return BlockchainHash::updateOrCreate(
            ['hash' => $data['hash']],
            [
                'type' => $data['type'],
                'user_id' => $data['user_id'] ?? null,
                'document_id' => $data['document_id'] ?? null,
                'blockchain_tx' => $data['blockchain_tx'] ?? null,
                'signed_at' => $data['signed_at'] ?? now(),
            ]
        );
    }
}
