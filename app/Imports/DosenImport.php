<?php

namespace App\Imports;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Maatwebsite\Excel\Concerns\ToModel;
use Maatwebsite\Excel\Concerns\WithHeadingRow;

class DosenImport implements ToModel, WithHeadingRow
{
    public function model(array $row)
    {
        // Cek jika email sudah ada, skip
        if (User::where('email', $row['email'])->exists()) {
            return null;
        }

        $user = new User([
            'name' => $row['name'],
            'email' => $row['email'],
            'nip' => $row['nip'] ?? null,
            'password' => Hash::make($row['password'] ?? 'password123'),
            'is_login' => false,
        ]);
        $user->save();
        $user->generateKeyPair();
        $user->roles()->attach(2); // 2 = dosen

        return $user;
    }
}
