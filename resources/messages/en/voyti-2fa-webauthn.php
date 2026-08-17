<?php

declare(strict_types=1);

return [
    // WebauthnTwoFactorMethod
    'voyti-2fa-webauthn.view.two_factor_webauthn.button_label' => 'Security key',
    'voyti-2fa-webauthn.view.two_factor_webauthn.method_name' => 'Security key',

    // WebAuthn setup fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro' => 'Register a security key or passkey to protect your account.',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_button' => 'Register security key',
    'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed' => 'Registration failed. Please try again.',

    // WebAuthn confirm fragment
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro' => "Confirm it's you by touching your security key or using your passkey.",
    'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message' => 'Authentication failed. Please try again.',

    // WebauthnService
    'voyti-2fa-webauthn.error.missing_challenge' => 'The security key check has expired. Please try again.',
    'voyti-2fa-webauthn.error.verification_failed' => 'The security key could not be verified. Please try again.',
    'voyti-2fa-webauthn.error.credential_not_found' => 'No matching security key was found for this account.',
];
