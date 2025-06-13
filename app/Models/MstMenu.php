<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MstMenu extends Model
{
    use HasFactory;

    protected $table = 'mst_menu';

    protected $fillable = ['name', 'description', 'position', 'status'];
}
