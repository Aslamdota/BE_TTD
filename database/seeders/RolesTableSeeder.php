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
            ['name' => 'signer', 'description' => 'signer'],
        ];

        foreach ($roles as $role) {
            Role::create($role);
        }
    }
}
