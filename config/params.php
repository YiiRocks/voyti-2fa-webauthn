<?php

declare(strict_types=1);

use YiiRocks\Voyti\TwoFactor\Webauthn\Controller\WebauthnController;
use Yiisoft\Router\Route;

return [
    'yiirocks/voyti' => [
        // Setup routes spliced into voyti-2fa's settings/ group (RequireLoginMiddleware) with no host
        // wiring. The guest-accessible confirmation fragment is a top-level route (see routes.php).
        'twoFactorMethodRoutes' => [
            Route::get('two-factor/webauthn/')
                ->name('voyti/user-two-factor-webauthn')
                ->action([WebauthnController::class, 'settings']),
            Route::post('two-factor/webauthn/register')
                ->name('voyti/user-two-factor-webauthn-register')
                ->action([WebauthnController::class, 'register']),
            Route::get('two-factor/webauthn/reauth')
                ->name('voyti/user-two-factor-webauthn-reauth')
                ->action([WebauthnController::class, 'reauth']),
        ],
    ],
];
