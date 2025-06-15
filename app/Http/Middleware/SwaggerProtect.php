<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SwaggerProtect
{
    protected array $blockedUserAgents = [
        'sqlmap',
        'nmap',
        'curl',
        'python-requests',
        'nikto',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $userAgent = strtolower($request->header('User-Agent', ''));
        foreach ($this->blockedUserAgents as $badAgent) {
            if (str_contains($userAgent, $badAgent)) {
                return response('Access denied: Bot access not allowed.', 403);
            }
        }

        if (!$request->isSecure() && app()->environment('production')) {
            return response('HTTPS is required for Swagger access.', 403);
        }

        $validUser = env('SWAGGER_USER', 'defaultuser');
        $validPass = env('SWAGGER_PASS', 'defaultpass');

        $providedUser = $request->getUser();
        $providedPass = $request->getPassword();

        if (
            !$this->secureCompare((string) $providedUser, (string) $validUser) ||
            !$this->secureCompare((string) $providedPass, (string) $validPass)
        ) {
            return response('Unauthorized.', 401, [
                'WWW-Authenticate' => 'Basic realm="Swagger Protected Area"',
            ]);
        }

        return $next($request);
    }

    protected function secureCompare($a, $b): bool
    {
        return hash_equals((string) $a, (string) $b);
    }
}
