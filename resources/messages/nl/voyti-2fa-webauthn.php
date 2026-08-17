<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Beveiligingssleutel',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Beveiligingssleutel',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Registreer een beveiligingssleutel of passkey om uw account te beschermen.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Beveiligingssleutel registreren',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'Registratie mislukt. Probeer het opnieuw.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => 'Bevestig dat u het bent door uw beveiligingssleutel aan te raken of uw passkey te gebruiken.',
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'Authenticatie mislukt. Probeer het opnieuw.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'De controle van de beveiligingssleutel is verlopen. Probeer het opnieuw.',
    'voyti-2fa-webauthn.error.verification_failed' => 'De beveiligingssleutel kon niet worden geverifieerd. Probeer het opnieuw.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'Er is geen overeenkomende beveiligingssleutel gevonden voor dit account.',
];
