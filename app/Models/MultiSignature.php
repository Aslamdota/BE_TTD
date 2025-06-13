<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MultiSignature extends Model
{
    use HasFactory;

    protected $fillable = [
        'document_id', 'signers_order', 'current_signer_index', 'status'
    ];

    protected $casts = [
        'signers_order' => 'array'
    ];

    public function document()
    {
        return $this->belongsTo(Document::class);
    }

    public function getCurrentSignerAttribute()
    {
        $signerId = $this->signers_order[$this->current_signer_index];
        return User::find($signerId);
    }
}
