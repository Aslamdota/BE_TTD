<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CorsOptions
{
    public function handle(Request $request, Closure $next)
    {
        $allowedOrigins = ['https://virsign.netlify.app', 'http://localhost:5173'];
        $origin = $request->headers->get('Origin');

        if ($request->isMethod('OPTIONS')) {
            $response = response()->noContent();
        } else {
            $response = $next($request);
        }

        if (in_array($origin, $allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
            $response->headers->set('Vary', 'Origin');
        }

        return $response;
    }
}