<?php

namespace App\Services;

use App\Events\TransactionEvent;
use App\Http\Resources\MsgResource;
use App\Jobs\NotifyTransactionJob;
use App\Jobs\TransactionJob;
use App\Repositories\TransactionRepository;
use App\Repositories\UserRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class SendTransactionService
{
    private $transactionRepository, $userRepository, $requestMockyUrlService;

    public function __construct(TransactionRepository $transactionRepository, UserRepository $userRepository, RequestMockyUrlService $requestMockyUrlService)
    {
        $this->transactionRepository = $transactionRepository;
        $this->userRepository = $userRepository;
        $this->requestMockyUrlService = $requestMockyUrlService;
    }

    public function execute(array $data): JsonResponse
    {
        return DB::transaction(function () use ($data) {
            //Detail the payer user
            $payer = $this->userRepository->findByIdAndType($data['payer'], 'user');
            if (!$payer) {
                return MsgResource::make('Origin error', 400, 'The payer is not a user.');
            }

            //Detail the payee user
            $payee = $this->userRepository->findById($data['payee']);
            if (!$payer) {
                return MsgResource::make('Origin error', 422, 'The selected payer is invalid.');
            }

            //Check if the payer and payee are the same
            if ($payee['id'] == $payer['id']) {
                return MsgResource::make('Origin error', 422, 'The payee and payer must be different.');
            }

            //Check if the value is positive
            if ($data['value'] < 0.01) {
                return MsgResource::make('Origin error', 422, 'The value must be at least 0.01.');
            }

            //Gets from cache or entity the current balance
            $payerBalance = Cache::rememberForever(config('pp.cache.user-balance'). $payer['id'], function () use ($payer) {
                return $payer['balance'];
            });

            //Check if the user has balance available
            if ($payerBalance < $data['value']) {
                return MsgResource::make('Value error', 400, 'Insufficient funds.');
            }
            
            //Execute the authorization service
            $request = $this->requestMockyUrlService->execute(config('pp.integration.authorization'))->getOriginalContent();
            if($request['status'] != 200) {
                return MsgResource::make('Authorization error', 401, 'Not Authorized.');
            }

            //Store the new balance of user
            Cache::put(config('pp.cache.user-balance'). $payer['id'], $payer['balance'] - $data['value']);

            //Create the transaction
            $transaction = $this->transactionRepository->store($data['payer'], $data['payee'], $data['value']);
            if (!$transaction) {
                DB::rollBack();
                Cache::put(config('pp.cache.user-balance'). $payer['id'], $payer['balance'] + $data['value']);
                return MsgResource::make('Transaction error', 400, 'Store transaction error. Try again.');
            }

            $data['transaction_id'] = $transaction;
            
            TransactionJob::dispatch($data)->afterCommit();

            return MsgResource::make('Success', 200, $transaction);
        });
    }
}
