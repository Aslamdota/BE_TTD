<?php

namespace App\Http\Middleware;

use Closure;

class CorsOptions
{
    public function handle($request, Closure $next)
    {
        if ($request->isMethod('OPTIONS')) {
            return response('', 204)
                ->header('Access-Control-Allow-Origin', 'https://virsign.netlify.app')
                ->header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, PUT, DELETE')
                ->header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
                ->header('Access-Control-Allow-Credentials', 'true');
        }

        return $next($request);
    }
}