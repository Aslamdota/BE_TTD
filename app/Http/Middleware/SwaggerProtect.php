<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SwaggerProtect
{
    protected array $allowedIps = [
        '127.0.0.1',
        '::1',
        '192.168.101.15',
    ];

    protected array $blockedUserAgents = [
        'sqlmap',
        'nmap',
        'curl',
        'python-requests',
        'nikto',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        if (!in_array($request->ip(), $this->allowedIps)) {
            return response('Access denied: IP not allowed.', 403);
        }

        $userAgent = strtolower($request->header('User-Agent', ''));
        foreach ($this->blockedUserAgents as $badAgent) {
            if (str_contains($userAgent, $badAgent)) {
                return response('Access denied: Bot access not allowed.', 403);
            }
        }

        $validUser = 'sigithd';
        $validPass = 'sigithardianto07@';

        $providedUser = $request->getUser();
        $providedPass = $request->getPassword();

        if (!$this->secureCompare($providedUser, $validUser) || !$this->secureCompare($providedPass, $validPass)) {
            return response('Unauthorized.', 401, [
                'WWW-Authenticate' => 'Basic realm="Swagger Protected Area"',
            ]);
        }

        return $next($request);
    }

    protected function secureCompare($a, $b): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }

        if (strlen($a) !== strlen($b)) {
            return false;
        }

        $res = 0;
        for ($i = 0; $i < strlen($a); $i++) {
            $res |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $res === 0;
    }
}
