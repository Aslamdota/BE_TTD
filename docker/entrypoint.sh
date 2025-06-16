#!/bin/bash

# Install dependencies if vendor not exists
if [ ! -d "vendor" ]; then
    composer install --no-interaction --prefer-dist --optimize-autoloader
fi

# Storage link
php artisan storage:link || true

# Clear caches
php artisan config:clear
php artisan cache:clear

# Start supervisor (nginx + php-fpm)
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
