<?php

namespace App\Repositories;

use App\Models\Transaction;
use App\Repositories\Interfaces\TransactionInterface;

class TransactionRepository implements TransactionInterface
{
    private $transaction;

    public function __construct(Transaction $transaction)
    {
        $this->transaction = $transaction;
    }

    public function store($payer_id, $payee_id, $value): int
    {
        $this->transaction->payer_id = $payer_id;
        $this->transaction->payee_id = $payee_id;
        $this->transaction->value = $value;
        $this->transaction->status = $this->transaction::$WAITING_FOR_TRANSACTION;
        $this->transaction->save();
        return $this->transaction->id;
    }
    
    public function doneTransaction($transaction_id): bool
    {
        return $this->updateWaitingForTransactionByStatus($transaction_id, $this->transaction::$DONE);
    }

    public function errorTransaction($transaction_id): bool
    {
        return $this->updateWaitingForTransactionByStatus($transaction_id, $this->transaction::$ERROR);
    }

    private function updateWaitingForTransactionByStatus($transaction_id, $status): bool
    {
        return $this->transaction
            ->where('id', $transaction_id)
            ->update(['status' => $status]);
    }
}
