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
            $response = Http::withToken(env('PINATA_JWT'))
                ->withHeaders([
                    'Accept' => '*/*',
                ])
                ->withOptions(['stream' => true])
                ->get($pinataGateway);

            if (!$response->successful()) {
                return response()->json(['message' => 'Gagal mengambil file dari IPFS'], 502);
            }

            return new StreamedResponse(function () use ($response) {
                fpassthru($response->toPsrResponse()->getBody()->detach());
            }, 200, [
                'Content-Type' => $response->header('Content-Type'),
                'Content-Disposition' => 'inline; filename="' . $cid . '"',
            ]);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Terjadi kesalahan: ' . $e->getMessage()], 500);
        }
    }
}
