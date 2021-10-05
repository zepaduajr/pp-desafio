<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Transaction extends Model
{
    use HasFactory;

    public static $WAITING_FOR_TRANSACTION = 1;
    public static $DONE = 2;
    public static $ERROR = 3;

    protected $table = 'transactions';

    protected $fillable = [
        'payer_id', 'payee_id', 'value', 'status'
    ];

    protected $casts = [
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function userPayer()
    {
        return $this->belongsTo(User::class, 'id', 'payer_id');
    }

    public function userPayee()
    {
        return $this->belongsTo(User::class, 'id', 'payee_id');
    }
}
