<?php

declare(strict_types=1);

use Psr\Clock\ClockInterface;
use ReportUri\Passkeys\WebAuthn;
use YiiRocks\Voyti\TwoFactor\Webauthn\Controller\WebauthnController;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use YiiRocks\Voyti\TwoFactor\Webauthn\WebauthnTwoFactorMethod;
use YiiRocks\Voyti\VoytiConfig;
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\CategorySource;
use Yiisoft\Translator\Message\Php\MessageSource;
use Yiisoft\Translator\SimpleMessageFormatter;
use Yiisoft\Translator\TranslatorInterface;

/** @var array $params */

return [
    WebauthnService::class => static function (
        SessionInterface $session,
        TranslatorInterface $translator,
        ClockInterface $clock,
        VoytiConfig $voytiConfig,
    ): WebauthnService {
        // The relying-party id is the request domain, resolved per ceremony; the name is the app's.
        $factory = static fn(string $domain): WebAuthn => new WebAuthn($voytiConfig->appName, $domain, true);

        return new WebauthnService($session, $translator, $clock, $factory);
    },
    WebauthnController::class => WebauthnController::class,

    // Registers the WebAuthn method with the core registry via the `voyti.two-factor-method` tag.
    WebauthnTwoFactorMethod::class => [
        'class' => WebauthnTwoFactorMethod::class,
        'tags' => ['voyti.two-factor-method'],
    ],

    // Translation category source for this package's message files.
    'yiirocks/voyti-2fa-webauthn.translator' => [
        'definition' => static fn(): CategorySource => new CategorySource(
            'voyti-2fa-webauthn',
            new MessageSource(dirname(__DIR__) . '/resources/messages'),
            new SimpleMessageFormatter(),
        ),
        'tags' => ['translation.categorySource'],
    ],
];
