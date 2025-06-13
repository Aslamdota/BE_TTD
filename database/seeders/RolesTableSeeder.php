<?php

namespace Database\Seeders;

use App\Models\Role;
use Illuminate\Database\Seeder;

class RolesTableSeeder extends Seeder
{
    public function run()
    {
        $roles = [
            ['name' => 'admin', 'description' => 'Administrator'],
            ['name' => 'dosen', 'description' => 'Dosen/Pengajar'],
            ['name' => 'pimpinan', 'description' => 'Pimpinan Fakultas/Universitas'],
            ['name' => 'verifikator', 'description' => 'Verifikator Dokumen']
        ];

        foreach ($roles as $role) {
            Role::create($role);
        }
    }
}
