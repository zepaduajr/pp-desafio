<?php

namespace App\Repositories\Interfaces;

/**
 * Class TransactionInterface
 * @package namespace App\Repositories\Interfaces;
 */
interface TransactionInterface
{
    /**
     * Stores the transaction
     */
    public function store($payer_id, $payee_id, $value): int;
    /**
     * Update the transaction as done
     */
    public function doneTransaction($transaction_id): bool;
    /**
     * Update the transaction as error
     */
    public function errorTransaction($transaction_id): bool;
}
