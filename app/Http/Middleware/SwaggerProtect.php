<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SwaggerProtect
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->getUser();
        $pass = $request->getPassword();

        if ($user !== 'sigithd' || $pass !== 'sigithardianto07@') {
            return response('Unauthorized.', 401, [
                'WWW-Authenticate' => 'Basic realm="Swagger Protected Area"',
            ]);
        }

        return $next($request);
    }
}
