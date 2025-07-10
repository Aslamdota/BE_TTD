<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Services\EthFaucetService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;

class FaucetController extends Controller
{
    public function send(Request $request, EthFaucetService $faucet)
    {
        $user = auth()->user();
        if (!$user) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $request->validate([
            'address' => 'required|regex:/^0x[a-fA-F0-9]{40}$/i'
        ]);

        $address = strtolower($request->address);
        $userId = $user->id;
        $ip = $request->ip();

        $now = now();
        $expiresAt = $now->addHour();

        // === 1. Cek limit berdasarkan wallet address ===
        $cacheAddress = "faucet_wallet_" . $address;
        if (Cache::has($cacheAddress)) {
            $minutes = max(0, $now->diffInMinutes(Cache::get($cacheAddress)['expires_at']));
            return response()->json(['message' => "⏳ Wallet sudah request. Coba lagi dalam {$minutes} menit."], 429);
        }

        // === 2. Cek limit berdasarkan user ID ===
        $cacheUser = "faucet_user_" . $userId;
        if (Cache::has($cacheUser)) {
            $minutes = max(0, $now->diffInMinutes(Cache::get($cacheUser)['expires_at']));
            return response()->json(['message' => "⏳ Anda sudah request. Coba lagi dalam {$minutes} menit."], 429);
        }

        // === 3. Cek limit berdasarkan IP ===
        $cacheIp = "faucet_ip_" . $ip;
        if (Cache::has($cacheIp)) {
            $minutes = max(0, $now->diffInMinutes(Cache::get($cacheIp)['expires_at']));
            return response()->json(['message' => "⏳ IP Anda sudah request. Coba lagi dalam {$minutes} menit."], 429);
        }

        try {
            $txHash = $faucet->sendEth($address);

            $data = ['used' => true, 'expires_at' => $expiresAt];
            Cache::put($cacheAddress, $data, $expiresAt);
            Cache::put($cacheUser, $data, $expiresAt);
            Cache::put($cacheIp, $data, $expiresAt);

            return response()->json(['status' => 'ok', 'txHash' => $txHash]);
        } catch (\Exception $e) {
            return response()->json(['status' => 'fail', 'message' => $e->getMessage()], 500);
        }
    }
}
