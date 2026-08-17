<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Sicherheitsschlüssel',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Sicherheitsschlüssel',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Registrieren Sie einen Sicherheitsschlüssel oder Passkey, um Ihr Konto zu schützen.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Sicherheitsschlüssel registrieren',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'Die Registrierung ist fehlgeschlagen. Bitte versuchen Sie es erneut.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => 'Bestätigen Sie Ihre Identität, indem Sie Ihren Sicherheitsschlüssel berühren oder Ihren Passkey verwenden.',
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'Die Authentifizierung ist fehlgeschlagen. Bitte versuchen Sie es erneut.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'Die Überprüfung des Sicherheitsschlüssels ist abgelaufen. Bitte versuchen Sie es erneut.',
    'voyti-2fa-webauthn.error.verification_failed' => 'Der Sicherheitsschlüssel konnte nicht verifiziert werden. Bitte versuchen Sie es erneut.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'Für dieses Konto wurde kein passender Sicherheitsschlüssel gefunden.',
];
