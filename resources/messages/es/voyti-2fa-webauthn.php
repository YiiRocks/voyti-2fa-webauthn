<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Clave de seguridad',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Clave de seguridad',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Registre una clave de seguridad o una clave de acceso para proteger su cuenta.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Registrar clave de seguridad',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'El registro falló. Inténtelo de nuevo.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => 'Confirme que es usted tocando su clave de seguridad o usando su clave de acceso.',
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'La autenticación falló. Inténtelo de nuevo.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'La comprobación de la clave de seguridad ha caducado. Inténtelo de nuevo.',
    'voyti-2fa-webauthn.error.verification_failed' => 'No se pudo verificar la clave de seguridad. Inténtelo de nuevo.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'No se encontró ninguna clave de seguridad que coincida con esta cuenta.',
];
