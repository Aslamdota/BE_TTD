<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MstApi extends Model
{
    use HasFactory;

    protected $table = 'mst_api';

    protected $fillable = ['name', 'status'];

    public function keys()
    {
        return $this->hasMany(MstKeyApi::class, 'api_id');
    }
}
