<?php

declare(strict_types=1);

use YiiRocks\Voyti\TwoFactor\Webauthn\Controller\WebauthnController;
use YiiRocks\Voyti\VoytiRoutes;
use Yiisoft\Router\Group;
use Yiisoft\Router\Route;

/** @var array $params */

$voytiParams = $params['yiirocks/voyti'] ?? [];

return [
    // The login-confirmation fragment: fetched by voyti-2fa's session/confirm screen during the
    // two-factor step, when the user is still a guest - so it lives outside the settings/ group
    // (which requires login) but still under the web-middleware stack for session + CSRF access.
    // The setup routes live in the settings/ group, contributed via twoFactorMethodRoutes (params.php).
    Group::create()
        ->middleware(...VoytiRoutes::webMiddleware($voytiParams))
        ->routes(
            Route::get('confirm/webauthn')
                ->name('voyti/user-two-factor-webauthn-confirm')
                ->action([WebauthnController::class, 'confirm']),
        ),
];
