<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class BlockchainHash extends Model
{
    use HasFactory;

    protected $fillable = [
        'hash', 'type', 'user_id', 'document_id', 'blockchain_tx', 'signed_at'
    ];
}
