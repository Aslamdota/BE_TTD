## Setup

1. Clone repo ini
2. Copy `.env.example` ke `.env` dan isi variabel sesuai kebutuhan
3. Jalankan:
   ```
   composer install
   php artisan key:generate
   php artisan migrate --seed
   php artisan storage:link
   ```
4. Jalankan server:
   ```
   php artisan serve
   ```

## Testing

```
php artisan test
```

## Deploy

- Railway: pastikan variabel env sudah benar, deploy via GitHub.
- Jalankan migrasi di Railway Console:
  ```
  php artisan migrate --force
  php artisan db:seed --force
  ```