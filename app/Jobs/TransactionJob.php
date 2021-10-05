<?php

namespace App\Jobs;

use App\Repositories\TransactionRepository;
use App\Repositories\UserRepository;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class TransactionJob implements ShouldQueue, ShouldBeUnique
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private $data;

    /**
     * Create a new job instance.
     *
     * @return void
     */
    public function __construct($data)
    {
        $this->data = $data;
    }

    /**
     * Execute the Transaction job.
     *
     * @return void
     */
    public function handle(TransactionRepository $transactionRepository, UserRepository $userRepository)
    {
        return DB::transaction(function () use ($transactionRepository, $userRepository) {

            $userPayer = $userRepository->decreaseBalanceById($this->data['value'], $this->data['payer']);
            if (!$userPayer) {
                DB::rollback();
                $this->handleError($transactionRepository);
                return false;
            }
    
            $userPayee = $userRepository->increaseBalanceById($this->data['value'], $this->data['payee']);
            if (!$userPayee) {
                DB::rollback();
                $this->handleError($transactionRepository);
                return false;
            }

            $transaction = $transactionRepository->doneTransaction($this->data['transaction_id']);
            if (!$transaction) {
                DB::rollback();
                $this->handleError($transactionRepository);
                return false;
            }

            $payee = $userRepository->findById($this->data['payee']);
            
            $balance_payee = (Cache::has(config('pp.cache.user-balance'). $this->data['payee'])) ? Cache::get(config('pp.cache.user-balance'). $this->data['payee']) : $payee['balance'];
            
            Cache::put(config('pp.cache.user-balance'). $this->data['payee'], $balance_payee + $this->data['value']);
            
            NotifyTransactionJob::dispatch($payee['email']);

            return true;
        });
    }

    /**
     * Handle with errors
     */
    private function handleError(TransactionRepository $transactionRepository) 
    {
        if (Cache::has(config('pp.cache.user-balance'). $this->data['payer'])) {
            Cache::put(config('pp.cache.user-balance'). $this->data['payer'], Cache::get(config('pp.cache.user-balance'). $this->data['payer']) + $this->data['value']);
        }

        $transactionRepository->errorTransaction($this->data['transaction_id']);
    }
}
