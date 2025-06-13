<?php

namespace App\Providers;

use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Gate;
use App\Models\Document;
use App\Models\User;
use App\Policies\DocumentPolicy;
// Hapus: use Laravel\Passport\Passport;

class AuthServiceProvider extends ServiceProvider
{
    protected $policies = [
        Document::class => DocumentPolicy::class,
        // Jika tidak ada UserPolicy, hapus baris berikut
        // User::class => \App\Policies\UserPolicy::class,
    ];

    public function boot()
    {
        $this->registerPolicies();

        Gate::define('admin', function ($user) {
            return $user->roles()->where('name', 'admin')->exists();
        });

        Gate::define('dosen', function ($user) {
            return $user->roles()->where('name', 'dosen')->exists();
        });

        Gate::define('pimpinan', function ($user) {
            return $user->roles()->where('name', 'pimpinan')->exists();
        });

        Gate::define('verifikator', function ($user) {
            return $user->roles()->where('name', 'verifikator')->exists();
        });

        Gate::define('manage-users', function ($user) {
            return $user->roles()->where('name', 'admin')->exists();
        });

        Gate::define('manage-documents', function ($user) {
            return $user->roles()->whereIn('name', ['admin', 'pimpinan'])->exists();
        });

        Gate::define('verify-documents', function ($user) {
            return $user->roles()->where('name', 'verifikator')->exists();
        });
    }
}
