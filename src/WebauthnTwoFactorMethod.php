<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn;

use JsonException;
use Override;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\TwoFactorMethodInterface;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use Yiisoft\Json\Json;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Translator\TranslatorInterface;

/**
 * WebAuthn/passkey two-factor method (the `yiirocks/voyti-2fa-webauthn` package): verification runs
 * server-side against the user's enrolled public-key credentials via {@see WebauthnService}, the
 * settings screen runs the registration ceremony via the package's own controller, and - being
 * client-collected - login confirmation loads a fragment that performs `navigator.credentials.get()`
 * and posts the raw assertion body to the core's confirm route.
 */
final readonly class WebauthnTwoFactorMethod implements TwoFactorMethodInterface
{
    public function __construct(
        private WebauthnService $webauthnService,
    ) {}

    #[Override]
    public function getButtonLabel(TranslatorInterface $translator): string
    {
        return $translator->translate('voyti-2fa-webauthn.view.two_factor_webauthn.button_label', category: 'voyti-2fa-webauthn');
    }

    #[Override]
    public function getConfirmFragmentUrl(UrlGeneratorInterface $url): ?string
    {
        return $url->generate('voyti/user-two-factor-webauthn-confirm');
    }

    #[Override]
    public function getEnabledWithMethodName(TranslatorInterface $translator): string
    {
        return $translator->translate('voyti-2fa-webauthn.view.two_factor_webauthn.method_name', category: 'voyti-2fa-webauthn');
    }

    #[Override]
    public function getErrorMessage(): string
    {
        return $this->webauthnService->getErrorMessage();
    }

    #[Override]
    public function getName(): string
    {
        return 'webauthn';
    }

    #[Override]
    public function getReauthFragmentUrl(UrlGeneratorInterface $url): ?string
    {
        // Settings-screen re-authentication (disable / regenerate backup codes) for the logged-in
        // user; distinct from the guest-accessible login-confirm fragment.
        return $url->generate('voyti/user-two-factor-webauthn-reauth');
    }

    #[Override]
    public function getSettingsUrl(UrlGeneratorInterface $url): string
    {
        return $url->generate('voyti/user-two-factor-webauthn');
    }

    #[Override]
    public function isAvailable(): bool
    {
        return true;
    }

    #[Override]
    public function isCodeBased(): bool
    {
        return false;
    }

    #[Override]
    public function onAuthenticationStepStart(User $user): void {}

    #[Override]
    public function onDisable(User $user): void
    {
        $this->webauthnService->deleteAllCredentials($user);
    }

    #[Override]
    public function requiresCodeDelivery(): bool
    {
        return false;
    }

    #[Override]
    public function verify(User $user, array $data): bool
    {
        // The relying-party id is the request domain, so verification must run against the same domain
        // the assertion challenge was issued for (see WebauthnController's getGetArgs calls). The core
        // caller passes it in $data['domain']; without it the ceremony's rpIdHash never matches and
        // every assertion is rejected.
        $domain = is_string($data['domain'] ?? null) ? $data['domain'] : '';
        $payload = $data['payload'] ?? null;

        if (is_string($payload) && $payload !== '') {
            try {
                /** @var mixed $decoded */
                $decoded = Json::decode($payload);
            } catch (JsonException) {
                return $this->webauthnService->verify($user, [], $domain);
            }

            if (is_array($decoded)) {
                return $this->webauthnService->verify($user, $decoded, $domain);
            }
        }

        return $this->webauthnService->verify($user, [], $domain);
    }
}
