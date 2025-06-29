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
            AuditLog::create([
                'user_id' => Auth::id(),
                'action' => $request->method().' '.$request->path(),
                'description' => json_encode($request->all()),
                'ip_address' => $request->ip()
            ]);
        }

        return $response;
    }
}