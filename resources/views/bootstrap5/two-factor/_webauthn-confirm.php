<?php

declare(strict_types=1);

use Yiisoft\Html\Html;
use Yiisoft\Json\Json;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\View\WebView;
use Yiisoft\Yii\View\Renderer\Csrf;

/**
 * @var WebView $this
 * @var array<string, mixed> $data
 * @var TranslatorInterface $translator
 * @var Csrf $csrf
 */

echo Html::p($translator->translate('voyti-2fa-webauthn.view.two_factor_webauthn_confirm.intro', category: 'voyti-2fa-webauthn'));

$config = [
    // Json::encode() only reads public properties via get_object_vars(), so passing
    // the Csrf object itself would silently serialize as {} - force the string value.
    'csrfToken' => (string) $csrf,
    'formSubmitUrl' => $data['formSubmitUrl'],
    'publicKey' => $data['requestOptions'],
    'errorMessage' => $data['errorMessage'],
    // Unique per render, so re-executing this exact script is a no-op while a freshly fetched
    // fragment (a different action) runs a new ceremony against its own challenge.
    'nonce' => bin2hex(random_bytes(8)),
];
$configJson = Json::htmlEncode($config);

// One fragment serves both contexts: login confirmation (voyti-2fa's session/confirm screen) and the
// settings-screen re-authentication for disable / regenerate backup codes. The embedding page marks
// its host container with data-voyti-2fa-assertion-host and, on the settings screen, sets the POST
// target via data-voyti-2fa-submit-url; login falls back to the server-provided confirm URL. The
// ceremony runs automatically on injection (the loader re-executes injected <script> nodes), guarded
// by a per-render nonce so it fires once per fetch.
$js = <<<JS
    (() => {
        const cfg = {$configJson};

        const container = document.querySelector('[data-voyti-2fa-assertion-host]');
        if (!container || container.dataset.voytiWebauthnCeremony === cfg.nonce) {
            return;
        }
        container.dataset.voytiWebauthnCeremony = cfg.nonce;

        const settingsSubmitUrl = container.getAttribute('data-voyti-2fa-submit-url');
        const submitUrl = settingsSubmitUrl || cfg.formSubmitUrl;

        const bufToB64 = buffer => {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            const chunkSize = 0x8000;
            for (let i = 0; i < bytes.length; i += chunkSize) {
                binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
            }
            return btoa(binary);
        };

        // The server serializes binary members (challenge, credential ids) as base64url strings;
        // navigator.credentials.get() requires them as ArrayBuffers.
        const b64ToBuf = value => {
            const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i += 1) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        };

        (async () => {
            try {
                const publicKey = cfg.publicKey.publicKey;
                publicKey.challenge = b64ToBuf(publicKey.challenge);
                if (Array.isArray(publicKey.allowCredentials)) {
                    publicKey.allowCredentials.forEach(cred => {
                        cred.id = b64ToBuf(cred.id);
                    });
                }

                const assertion = await navigator.credentials.get(cfg.publicKey);
                if (!assertion) {
                    throw new Error();
                }

                const response = await fetch(submitUrl, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': cfg.csrfToken,
                    },
                    body: JSON.stringify({
                        id: bufToB64(assertion.rawId),
                        clientDataJSON: bufToB64(assertion.response.clientDataJSON),
                        authenticatorData: bufToB64(assertion.response.authenticatorData),
                        signature: bufToB64(assertion.response.signature),
                    }),
                });

                if (response.redirected) {
                    window.location.href = response.url;
                    return;
                }

                if (!response.ok) {
                    throw new Error();
                }

                // A non-redirect response means verification failed and the step was re-rendered, so
                // fetch a fresh challenge. On the settings screen the host page is a GET, so reloading
                // is safe. The login-confirmation screen, however, is the body of the login POST -
                // reloading it resubmits the login form with an already-spent reCAPTCHA token, which
                // then fails ("CAPTCHA verification failed"). Navigate to the confirmation route with a
                // GET instead, so a fresh challenge is issued without touching the login form.
                if (settingsSubmitUrl) {
                    window.location.reload();
                } else {
                    window.location.href = cfg.formSubmitUrl;
                }
            } catch {
                alert(cfg.errorMessage);
            }
        })();
    })();
    JS;

echo Html::script($js)->render();
