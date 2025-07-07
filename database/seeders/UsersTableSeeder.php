<?php
namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UsersTableSeeder extends Seeder
{
    public function run()
    {
        if (!User::where('email', 'admin@iwu.ad.id')->exists()) {
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
            $dosen->roles()->attach(2);
        }

        if (!User::where('email', 'developertua@iwu.local')->exists()) {
            $developer = User::create([
                'name' => 'Developer',
                'email' => 'developertua@iwu.local',
                'password' => Hash::make('Sigithardianto10@'),
                'nip' => '2233445566',
                'is_login' => false
            ]);

            $developer->generateKeyPair();

            $developer->roles()->attach([1, 2]);
        }

        if (!User::where('email', 'developermuda@iwu.local')->exists()) {
            $developer = User::create([
                'name' => 'Developer',
                'email' => 'developermuda@iwu.local',
                'password' => Hash::make('Aslamdeveloper2025@'),
                'nip' => '1122334455',
                'is_login' => false
            ]);

            $developer->generateKeyPair();

            $developer->roles()->attach([1, 2]);
        }
        
        if (!User::where('email', 'alianiadiku@iwu.id')->exists()) {
            $developer = User::create([
                'name' => 'Aliani Natasania',
                'email' => 'alianiadiku@iwu.id',
                'password' => Hash::make('password123'),
                'nip' => '321321312311',
                'is_login' => false
            ]);

            $developer->generateKeyPair();

            $developer->roles()->attach([1]);
        }

        if (!User::where('email', 'archy@iwu.ac.id')->exists()) {
            $developer = User::create([
                'name' => 'Archy Renaldy Pratama Nugraha, S.Kom., M.T',
                'email' => 'archy@iwu.ac.id',
                'password' => Hash::make('arpn1234'),
                'nip' => '123456789',
                'is_login' => false
            ]);

            $developer->generateKeyPair();

            $developer->roles()->attach([1, 2]);
        }
    }
}
