<?php

return [
    'default' => 'default',

    'documentations' => [
        'default' => [
            'api' => [
                'title' => 'E-TTD API Documentation',
                'version' => '1.0.0',
                'description' => 'API documentation for Electronic Signature System with Blockchain',
                'termsOfService' => 'https://example.com/terms',
                'contact' => [
                    'name' => 'API Support',
                    'email' => 'support@example.com',
                ],
                'license' => [
                    'name' => 'Apache 2.0',
                    'url' => 'http://www.apache.org/licenses/LICENSE-2.0.html',
                ],
            ],

            'routes' => [
                'api' => 'api/documentation',
                'docs' => 'docs',
                'oauth2_callback' => 'api/oauth2-callback',
                'middleware' => [
                    'api' => [],
                    'asset' => [],
                    'docs' => [],
                    'oauth2_callback' => [],
                ],
                'group_by' => 'tag',
            ],

            'paths' => [
                'docs' => storage_path('api-docs'),
                'annotations' => [
                    base_path('app'),
                    base_path('routes'),
                ],
                'models' => [
                    base_path('app/Models'),
                ],
                'excludes' => [
                    base_path('app/Exceptions'),
                    base_path('app/Console'),
                ],
                'base' => '/',
                'docs_json' => 'api-docs.json',
                'docs_yaml' => 'api-docs.yaml',
            ],

            'security' => [
                'sanctum' => [
                    'type' => 'http',
                    'description' => 'Use Bearer token from Sanctum login.',
                    'in' => 'header',
                    'scheme' => 'bearer',
                    'bearerFormat' => 'JWT',
                ],
            ],

            // PROXY HARUS ADA, walau tidak dipakai, set enabled ke false
            'proxy' => [
                'enabled' => false,
                'host' => null,
                'port' => null,
                'username' => null,
                'password' => null,
            ],
        ],
    ],

    'defaults' => [
        'routes' => [
            'docs' => 'docs',
            'oauth2_callback' => 'api/oauth2-callback',
            'middleware' => [
                'api' => [],
                'asset' => [],
                'docs' => [],
                'oauth2_callback' => [],
            ],
        ],
        'paths' => [
            'docs' => storage_path('api-docs'),
            'annotations' => [
                base_path('app'),
            ],
            'models' => [
                base_path('app/Models'),
            ],
            'excludes' => [
                base_path('app/Exceptions'),
                base_path('app/Console'),
            ],
            'base' => '/',
            'docs_json' => 'api-docs.json',
            'docs_yaml' => 'api-docs.yaml',
        ],
        'security' => [
            'sanctum' => [
                'type' => 'http',
                'description' => 'Use Bearer token from Sanctum login.',
                'in' => 'header',
                'scheme' => 'bearer',
                'bearerFormat' => 'JWT',
            ],
        ],
    ],
];
