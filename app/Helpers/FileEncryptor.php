<?php

namespace App\Helpers;

class FileEncryptor
{
    public static function encrypt($inputPath, $outputPath, $key)
    {
        $data = file_get_contents($inputPath);
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        file_put_contents($outputPath, $iv . $encrypted);
    }

    public static function decrypt($inputPath, $outputPath, $key)
    {
        $data = file_get_contents($inputPath);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
        file_put_contents($outputPath, $decrypted);
    }
}