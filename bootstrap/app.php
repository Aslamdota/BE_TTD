<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Middleware\HandleCors;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend([]);

        $middleware->group('api', [
            HandleCors::class,
            EnsureFrontendRequestsAreStateful::class,
            ThrottleRequests::class . ':api',
            SubstituteBindings::class,
        ]);

        $middleware->validateCsrfTokens(except: ['*']);

        $middleware->alias([
            'swagger.protect' => \App\Http\Middleware\SwaggerProtect::class,
            'cors.options' => \App\Http\Middleware\CorsOptions::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
  
    })
    ->create();
