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
        $expiresAt = $now->copy()->addHour();

        $checkThrottle = function ($cacheKey, $label) use ($now) {
            if (Cache::has($cacheKey)) {
                $data = Cache::get($cacheKey);
                if (isset($data['expires_at']) && $data['expires_at'] instanceof \Carbon\Carbon) {
                    if ($data['expires_at']->greaterThan($now)) {
                        $minutes = $now->diffInMinutes($data['expires_at']);
                        return response()->json([
                            'message' => "⏳ {$label} sudah request. Coba lagi dalam {$minutes} menit."
                        ], 429);
                    } else {
                        Cache::forget($cacheKey);
                    }
                } else {
                    Cache::forget($cacheKey);
                }
            }
            return null;
        };

        $cacheAddress = "faucet_wallet_" . $address;
        $cacheUser = "faucet_user_" . $userId;
        $cacheIp = "faucet_ip_" . $ip;

        if ($response = $checkThrottle($cacheAddress, 'Wallet')) return $response;
        if ($response = $checkThrottle($cacheUser, 'Anda')) return $response;
        if ($response = $checkThrottle($cacheIp, 'IP Anda')) return $response;

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
