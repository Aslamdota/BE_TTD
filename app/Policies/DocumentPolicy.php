<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Document;
use Illuminate\Auth\Access\HandlesAuthorization;

class DocumentPolicy
{
    use HandlesAuthorization;

    public function view(User $user, Document $document)
    {
        return $user->id === $document->creator_id ||
               $document->signatures()->where('user_id', $user->id)->exists();
    }

    public function sign(User $user, Document $document)
    {
        return $document->signatures()
            ->where('user_id', $user->id)
            ->where('status', 'pending')
            ->exists();
    }
}
