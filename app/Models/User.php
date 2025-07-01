<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $fillable = [
        'name', 'email', 'password', 'nip', 'public_key', 'private_key', 'is_login', 'last_activity'
    ];

    protected $hidden = [
        'password', 'remember_token', 'private_key'
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }

    public function documents()
    {
        return $this->hasMany(Document::class, 'creator_id');
    }

    public function signatures()
    {
        return $this->hasMany(Signature::class);
    }

    public function generateKeyPair()
    {
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        // Tambahkan config file jika di Windows
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $config['config'] = 'C:/Xampp/apache/conf/openssl.cnf';
        }

        $res = openssl_pkey_new($config);

        // Cek apakah resource berhasil dibuat
        if (!$res) {
            throw new Exception('Failed to generate private key: ' . openssl_error_string());
        }

        $privateKey = '';
        if (!openssl_pkey_export($res, $privateKey, null, $config)) {
            throw new Exception('Failed to export private key: ' . openssl_error_string());
        }

        $publicKeyDetails = openssl_pkey_get_details($res);
        if (!$publicKeyDetails) {
            throw new Exception('Failed to get public key details: ' . openssl_error_string());
        }

        $publicKey = $publicKeyDetails['key'];

        $this->public_key = $publicKey;
        $this->private_key = $privateKey;

        // Bersihkan resource
        openssl_pkey_free($res);
    }

    public function passkeys()
    {
        return $this->hasMany(Passkey::class);
    }

    public function activePasskey()
    {
        return $this->passkeys()->where('status', 'active')->latest('created_at')->first();
    }
}
