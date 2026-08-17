<?php

declare(strict_types=1);

use YiiRocks\Voyti\Helper\LinkButtonHelper;
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

echo Html::p($translator->translate('voyti-2fa-webauthn.view.two_factor_webauthn.setup_intro', category: 'voyti-2fa-webauthn'));

echo Html::button($translator->translate('voyti-2fa-webauthn.view.two_factor_webauthn.register_button', category: 'voyti-2fa-webauthn'))
    ->id('voyti-2fa-webauthn-register')
    ->class(LinkButtonHelper::submitButtonClass());

$config = [
    // Json::encode() only reads public properties via get_object_vars(), so passing
    // the Csrf object itself would silently serialize as {} - force the string value.
    'csrfToken' => (string) $csrf,
    'registerUrl' => $data['registerUrl'],
    'publicKey' => $data['requestOptions'],
    'errorMessage' => $data['errorMessage'],
];
$configJson = Json::htmlEncode($config);

// The fragment is re-injected on every method switch, so the handler is guarded per-element
// (the freshly-injected button lacks the marker and gets bound anew).
$js = <<<JS
    (() => {
        const cfg = {$configJson};

        const button = document.getElementById('voyti-2fa-webauthn-register');
        if (!button || button.dataset.voytiWebauthnRegisterBound) {
            return;
        }
        button.dataset.voytiWebauthnRegisterBound = '1';

        const bufToB64 = buffer => {
            const bytes = new Uint8Array(buffer);
            let binary = '';
            const chunkSize = 0x8000;
            for (let i = 0; i < bytes.length; i += chunkSize) {
                binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
            }
            return btoa(binary);
        };

        // The server serializes binary members (challenge, user.id, credential ids) as base64url
        // strings; navigator.credentials.create() requires them as ArrayBuffers.
        const b64ToBuf = value => {
            const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i += 1) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes.buffer;
        };

        button.addEventListener('click', async () => {
            button.disabled = true;

            try {
                const publicKey = cfg.publicKey.publicKey;
                publicKey.challenge = b64ToBuf(publicKey.challenge);
                publicKey.user.id = b64ToBuf(publicKey.user.id);
                if (Array.isArray(publicKey.excludeCredentials)) {
                    publicKey.excludeCredentials.forEach(cred => {
                        cred.id = b64ToBuf(cred.id);
                    });
                }

                const credential = await navigator.credentials.create(cfg.publicKey);
                if (!credential) {
                    throw new Error();
                }

                const form = document.createElement('form');
                form.method = 'POST';
                form.action = cfg.registerUrl;
                form.style.display = 'none';

                const add = (name, value) => {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = name;
                    input.value = value;
                    form.appendChild(input);
                };

                add('_csrf', cfg.csrfToken);
                add('clientDataJSON', bufToB64(credential.response.clientDataJSON));
                add('attestationObject', bufToB64(credential.response.attestationObject));

                document.body.appendChild(form);
                form.submit();
            } catch {
                alert(cfg.errorMessage);
                button.disabled = false;
            }
        });
    })();
    JS;

echo Html::script($js)->render();
