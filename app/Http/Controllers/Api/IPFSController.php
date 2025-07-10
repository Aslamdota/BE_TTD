<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class IPFSController extends Controller
{
    public function fetch($cid)
    {
        $pinataGateway = "https://gateway.pinata.cloud/ipfs/{$cid}";

        try {
            $response = Http::withHeaders([
                    'Accept' => '*/*',
                ])
                ->withOptions(['stream' => true])
                ->timeout(15)
                ->get($pinataGateway);

            if (!$response->successful()) {
                \Log::error('IPFS Fetch Failed', [
                    'cid' => $cid,
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
                return response()->json(['message' => 'Gagal mengambil file dari IPFS'], 502);
            }

            $contentType = $response->header('Content-Type') ?? 'application/octet-stream';

            return new StreamedResponse(function () use ($response) {
                fpassthru($response->toPsrResponse()->getBody()->detach());
            }, 200, [
                'Content-Type' => $contentType,
                'Content-Disposition' => 'inline; filename="' . $cid . '"',
            ]);
        } catch (\Exception $e) {
            \Log::error('IPFS Fetch Exception', ['cid' => $cid, 'error' => $e->getMessage()]);
            return response()->json(['message' => 'Terjadi kesalahan: ' . $e->getMessage()], 500);
        }
    }
}
