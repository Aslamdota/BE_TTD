<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Document extends Model
{
    use HasFactory;

    protected $fillable = [
        'title', 'file_path', 'hash', 'hash_verified', 'blockchain_tx', 'creator_id', 'status'
    ];

    public function creator()
    {
        return $this->belongsTo(User::class, 'creator_id');
    }

    public function signatures()
    {
        return $this->hasMany(Signature::class);
    }

    public function multiSignature()
    {
        return $this->hasOne(MultiSignature::class);
    }

    public function generateHash()
    {
        $fileContent = file_get_contents(storage_path('app/' . $this->file_path));
        $this->hash = hash('sha256', $fileContent);
        $this->save();
    }
}
