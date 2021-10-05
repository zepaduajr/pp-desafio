<?php

namespace App\Jobs;

use App\Services\RequestMockyUrlService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class NotifyTransactionJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private $email;

    /**
     * Create a new job instance.
     *
     * @return void
     */
    public function __construct($email)
    {
        $this->email = $email;
    }

    /**
     * Execute the job.
     *
     * @return void
     */
    public function handle(RequestMockyUrlService $requestMockyUrlService)
    {
        $request = $requestMockyUrlService->execute(config('pp.integration.notification'))->getOriginalContent();
        if ($request['status'] != 200) {
            Log::info('Notificação não enviada para o email ' . $this->email);
        } else {
            Log::info('Notificação enviada para o email ' . $this->email);
        }
    }
}
