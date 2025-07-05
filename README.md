# VirSign Backend (Laravel)

Aplikasi backend Electronic Signature System (VirSign) berbasis Laravel, terintegrasi Blockchain, mendukung multi-role (admin, signer/dosen), API dokumentasi Swagger, dan siap untuk deployment Docker/Railway.

---

## 🚀 Fitur Utama

- Manajemen user, dokumen, tanda tangan (TTD), passkey, dan blockchain
- Role-based access (admin, signer/dosen)
- API RESTful dengan dokumentasi Swagger (OpenAPI)
- Support Docker & Railway deployment
- Unit test & seed data siap pakai

---

## ⚡️ Persiapan Awal

### 1. **Clone Repository**

```bash
git clone https://github.com/yourusername/virsign-backend.git
cd virsign-backend
```

### 2. **Copy & Edit Environment**

```bash
cp .env.example .env
```
Edit `.env` sesuai kebutuhan (database, mail, blockchain, dsb).

### 3. **Install Dependency**

```bash
composer install
```

### 4. **Generate Key**

```bash
php artisan key:generate
```

### 5. **Migrasi & Seed Database**

```bash
php artisan migrate --seed
```

### 6. **Link Storage**

```bash
php artisan storage:link
```

---

## 🖥️ Menjalankan Server Lokal

```bash
php artisan serve
```
Akses API di: [http://localhost:8000](http://localhost:8000)

---

## 🧪 Testing

```bash
php artisan test
```

---

## 🐳 Jalankan dengan Docker

1. **Build Docker image:**
    ```bash
    docker build -f dockerbackup/docker/Dockerfile -t virsign-backend .
    ```

2. **Jalankan container:**
    ```bash
    docker run -p 8080:80 --env-file .env virsign-backend
    ```

---

## 📖 Dokumentasi API (Swagger)

Setelah server berjalan, akses dokumentasi API di:
```
http://localhost:8000/api/documentation
```
atau sesuai domain Railway Anda.

---

## 🛠️ Deployment ke Railway

- Pastikan variabel `.env` sudah benar di Railway dashboard.
- Deploy via GitHub atau upload manual.
- Jalankan migrasi di Railway Console:
    ```bash
    php artisan migrate --force
    php artisan db:seed --force
    ```

---

## 📝 Catatan

- Untuk development, gunakan database lokal agar lebih stabil.
- Untuk production, pastikan semua variabel `.env` (database, mail, blockchain, dsb) sudah benar.
- Jika menggunakan Docker, pastikan file `docker/nginx.conf`, `docker/supervisord.conf`, dan `docker/entrypoint.sh` tersedia.

---

## 🤝 Kontribusi

Pull request dan issue sangat diterima!

---

## Lisensi

Proprietary - VirSign IWU 2025
