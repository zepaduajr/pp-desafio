<?php

/**
 * Environment variables customized - pp desafio
 */

return [
  'integration' => [
    'authorization' => env('URL_AUTHORIZATION', 'https://run.mocky.io/v3/8fafdd68-a090-496f-8c9a-3442cf30dae6'),
    'notification' => env('URL_NOTIFICATION', 'http://o4d9z.mocklab.io/notify')
  ],
  'cache' => [
    'user-balance' => 'user-balance-'
  ]
];
