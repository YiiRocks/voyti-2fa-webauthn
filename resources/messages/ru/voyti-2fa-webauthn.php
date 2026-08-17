<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Ключ безопасности',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Ключ безопасности',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Зарегистрируйте ключ безопасности или ключ доступа, чтобы защитить свой аккаунт.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Зарегистрировать ключ безопасности',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'Регистрация не удалась. Пожалуйста, попробуйте снова.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => 'Подтвердите, что это вы, коснувшись ключа безопасности или используя ключ доступа.',
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'Аутентификация не удалась. Пожалуйста, попробуйте снова.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'Срок действия проверки ключа безопасности истёк. Пожалуйста, попробуйте снова.',
    'voyti-2fa-webauthn.error.verification_failed' => 'Не удалось проверить ключ безопасности. Пожалуйста, попробуйте снова.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'Для этого аккаунта не найден подходящий ключ безопасности.',
];
