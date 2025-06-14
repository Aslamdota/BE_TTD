<?php

return [
    'default' => 'default',
    'documentations' => [
        'default' => [
            'api' => [
                'title' => env('APP_NAME', 'E-TTD API Documentation'),
                'version' => '1.0.0',
                'description' => 'API documentation for Electronic Signature System with Blockchain',
                'termsOfService' => '',
                'contact' => [
                    'email' => env('MAIL_FROM_ADDRESS', 'digisign.iwu@gmail.com')
                ],
                'license' => [
                    'name' => 'Proprietary',
                    'url' => ''
                ],
            ],
            'routes' => [
                'api' => 'api/documentation',
                'docs' => 'docs',
                'oauth2_callback' => 'api/oauth2-callback',
                'middleware' => [
                    'api' => ['web'],
                    'asset' => [],
                    'docs' => [],
                    'oauth2_callback' => [],
                ],            
            'enabled' => env('L5_SWAGGER_ENABLE', true),
            ],
            'paths' => [
                'docs' => storage_path('api-docs'),
                'docs_json' => 'api-docs.json',
                'docs_yaml' => 'api-docs.yaml',
                'format_to_use_for_docs' => env('L5_SWAGGER_FORMAT_TO_USE_FOR_DOCS', 'json'),
                'annotations' => [
                    // base_path('app'),
                    base_path('app/Http/Controllers'),
                ],
                'excludes' => [
                    base_path('app/Exceptions'),
                    base_path('app/Providers'),
                ],
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
            'securityDefinitions' => [
                'securitySchemes' => [
                    'sanctum' => [
                        'type' => 'http',
                        'description' => 'Use Bearer token from Sanctum login.',
                        'in' => 'header',
                        'scheme' => 'bearer',
                        'bearerFormat' => 'JWT',
                    ],
                ],
            ],
            'ui' => [
                'display' => [
                    'dark_mode' => env('L5_SWAGGER_UI_DARK_MODE', false),
                    'doc_expansion' => env('L5_SWAGGER_UI_DOC_EXPANSION', 'none'),
                    'filter' => env('L5_SWAGGER_UI_FILTER', true),
                ],
                'authorization' => [
                    'persist_authorization' => env('L5_SWAGGER_UI_PERSIST_AUTHORIZATION', false),
                    'oauth2' => [
                        'use_pkce_with_authorization_code_grant' => false
                    ]
                ]
            ],
            'proxy' => env('L5_SWAGGER_PROXY', false),
            'operations_sort' => env('L5_SWAGGER_OPERATIONS_SORT', null),
            'validator_url' => env('L5_SWAGGER_VALIDATOR_URL', null),
            'generate_always' => env('L5_SWAGGER_GENERATE_ALWAYS', true),
            'generate_yaml_copy' => env('L5_SWAGGER_GENERATE_YAML_COPY', false),
            'swagger_version' => env('L5_SWAGGER_VERSION', \L5Swagger\Generator::OPEN_API_DEFAULT_SPEC_VERSION),
            'constants' => [
                'L5_SWAGGER_CONST_HOST' => env('L5_SWAGGER_CONST_HOST', env('APP_URL', 'https://bettd-production.up.railway.app')),
                'L5_SWAGGER_CONST_SCHEME' => env('L5_SWAGGER_SCHEME', 'https'),
            ],
        ],
    ],
    'defaults' => [
        'routes' => [
            'docs' => 'docs',
            'oauth2_callback' => 'api/oauth2-callback',
            'middleware' => [
                'api' => ['web'],
                'asset' => [],
                'docs' => [],
                'oauth2_callback' => [],
            ],        
        ],
        'paths' => [
            'docs' => storage_path('api-docs'),
            'views' => base_path('resources/views/vendor/l5-swagger'),
            'base' => env('L5_SWAGGER_BASE_PATH', null),
            'excludes' => [],
        ],
        'scanOptions' => [
            'analyser' => env('L5_SWAGGER_ANALYSER', null),
            'analysis' => env('L5_SWAGGER_ANALYSIS', null),
            'processors' => env('L5_SWAGGER_PROCESSORS', null),
            'pattern' => env('L5_SWAGGER_PATTERN', null),
            'open_api_spec_version' => env('L5_SWAGGER_OPEN_API_SPEC_VERSION', \L5Swagger\Generator::OPEN_API_DEFAULT_SPEC_VERSION),
        ],
        'securityDefinitions' => [
            'securitySchemes' => [
                'sanctum' => [
                    'type' => 'http',
                    'description' => 'Use Bearer token from Sanctum login.',
                    'in' => 'header',
                    'scheme' => 'bearer',
                    'bearerFormat' => 'JWT',
                ],
            ],
            'security' => [],
        ],
        'generate_always' => env('L5_SWAGGER_GENERATE_ALWAYS', true),
        'generate_yaml_copy' => env('L5_SWAGGER_GENERATE_YAML_COPY', false),
        'proxy' => env('L5_SWAGGER_PROXY', false),
        'additional_config_url' => null,
        'operations_sort' => env('L5_SWAGGER_OPERATIONS_SORT', null),
        'validator_url' => env('L5_SWAGGER_VALIDATOR_URL', null),
        'ui' => [
            'display' => [
                'dark_mode' => env('L5_SWAGGER_UI_DARK_MODE', false),
                'doc_expansion' => env('L5_SWAGGER_UI_DOC_EXPANSION', 'none'),
                'filter' => env('L5_SWAGGER_UI_FILTER', true),
                'show_extensions' => env('L5_SWAGGER_UI_SHOW_EXTENSIONS', true),
                'show_common_extensions' => env('L5_SWAGGER_UI_SHOW_COMMON_EXTENSIONS', true),
            ],
            'authorization' => [
                'persist_authorization' => env('L5_SWAGGER_UI_PERSIST_AUTHORIZATION', false),
                'oauth2' => [
                    'use_pkce_with_authorization_code_grant' => false,
                ],
            ],
        ],
        'constants' => [
            'L5_SWAGGER_CONST_HOST' => env('L5_SWAGGER_CONST_HOST', env('APP_URL', 'https://bettd-production.up.railway.app')),
            'L5_SWAGGER_CONST_SCHEME' => env('L5_SWAGGER_SCHEME', 'https'),
        ],
    ],
];