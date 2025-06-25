<?php
namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UsersTableSeeder extends Seeder
{
    public function run()
    {
        if (!User::where('email', 'admin@iwu.com')->exists()) {
            $admin = User::create([
                'name' => 'Admin',
                'email' => 'admin@iwu.ad.id',
                'password' => Hash::make('iwupaskal#5'),
                'nip' => '1234567890'
            ]);

            $admin->generateKeyPair();
            $admin->roles()->attach(1); // Admin role
        }

        if (!User::where('email', 'dosen@iwu.com')->exists()) {
            $dosen = User::create([
                'name' => 'Dosen Contoh',
                'email' => 'dosen@iwu.com',
                'password' => Hash::make('password123'),
                'nip' => '0987654321',
                'is_login' => false
            ]);

            $dosen->generateKeyPair();
            $dosen->roles()->attach(2); // Dosen role
        }
    }
}
