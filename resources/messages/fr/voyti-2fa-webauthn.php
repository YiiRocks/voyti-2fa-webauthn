<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Clé de sécurité',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Clé de sécurité',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Enregistrez une clé de sécurité ou une clé d\'accès pour protéger votre compte.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Enregistrer la clé de sécurité',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'L\'enregistrement a échoué. Veuillez réessayer.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => 'Confirmez qu\'il s\'agit bien de vous en touchant votre clé de sécurité ou en utilisant votre clé d\'accès.',
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'L\'authentification a échoué. Veuillez réessayer.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'Le contrôle de la clé de sécurité a expiré. Veuillez réessayer.',
    'voyti-2fa-webauthn.error.verification_failed' => 'La clé de sécurité n\'a pas pu être vérifiée. Veuillez réessayer.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'Aucune clé de sécurité correspondante n\'a été trouvée pour ce compte.',
];
