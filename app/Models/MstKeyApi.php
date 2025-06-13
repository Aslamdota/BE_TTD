<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MstKeyApi extends Model
{
    use HasFactory;

    protected $table = 'mst_key_api';

    protected $fillable = ['api_id', 'api_key', 'api_secret'];

    public function api()
    {
        return $this->belongsTo(MstApi::class, 'api_id');
    }
}
