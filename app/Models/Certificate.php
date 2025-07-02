<?php

namespace App\Models;
use Illuminate\Database\Eloquent\Model;

class Certificate extends Model
{
    protected $fillable = [
        'user_id', 'serial_number', 'issuer', 'valid_from', 'valid_to', 'status'
    ];

    public function user() 
    { 
        return $this->belongsTo(User::class)->withTrashed();
    }
}
