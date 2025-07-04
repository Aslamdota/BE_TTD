<?php

namespace App\Http\Middleware;

use Closure;
use App\Models\AuditLog;
use Illuminate\Support\Facades\Auth;

class AuditTrail
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        if (Auth::check()) {
            $user = Auth::user();
            $data = $request->except(['password', 'password_confirmation', 'token']);
            \App\Models\AuditLog::create([
                'user_id' => $user->id,
                'action' => $request->method().' '.$request->path(),
                'description' => json_encode($data),
                'ip_address' => $request->ip()
            ]);
        }

        return $response;
    }
}