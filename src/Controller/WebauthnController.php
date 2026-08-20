<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\Controller;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use YiiRocks\Voyti\Controller\RedirectTrait;
use YiiRocks\Voyti\Controller\RenderTrait;
use YiiRocks\Voyti\Helper\Views\MenuView;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\Service\FlashNotifier;
use YiiRocks\Voyti\TwoFactor\Form\TwoFactorCodeForm;
use YiiRocks\Voyti\TwoFactor\Helper\Views\IndexView;
use YiiRocks\Voyti\TwoFactor\Model\UserTwoFactor;
use YiiRocks\Voyti\TwoFactor\Service\BackupCodeService;
use YiiRocks\Voyti\TwoFactor\TwoFactorMethodInterface;
use YiiRocks\Voyti\TwoFactor\TwoFactorMethodRegistry;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use YiiRocks\Voyti\VoytiConfig;
use Yiisoft\Router\UrlGeneratorInterface;
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\User\CurrentUser;
use Yiisoft\Yii\View\Renderer\WebViewRenderer;

/**
 * Runs the WebAuthn two-factor flows: the setup screen (registration ceremony on the settings
 * page, which enables 2FA and reveals backup codes on the first enrolled key) and the login
 * confirmation fragment (assertion ceremony, posted to the core `voyti/session-confirm` route).
 */
final readonly class WebauthnController
{
    use RedirectTrait;
    use RenderTrait;

    /**
     * Mirrors `SessionController::SESSION_KEY_CREDENTIALS` (private there): the pending-login
     * details stored when a 2FA-enabled user submits the password step, needed here to resolve
     * which user's credentials the confirmation fragment must offer.
     */
    private const string SESSION_KEY_CREDENTIALS = 'credentials';

    public function __construct(
        private TranslatorInterface $translator,
        private WebViewRenderer $viewRenderer,
        private UrlGeneratorInterface $url,
        private VoytiConfig $config,
        private CurrentUser $currentUser,
        private ResponseFactoryInterface $responseFactory,
        private SessionInterface $session,
        private BackupCodeService $backupCodeService,
        private TwoFactorMethodRegistry $twoFactorMethods,
        private WebauthnService $webauthnService,
        private FlashNotifier $flashNotifier,
    ) {}

    public function confirm(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $credentialsValue */
        $credentialsValue = $this->session->get(self::SESSION_KEY_CREDENTIALS);
        $credentials = is_array($credentialsValue) ? $credentialsValue : [];
        /** @var mixed $loginValue */
        $loginValue = $credentials['login'] ?? '';
        $user = User::findByUsernameOrEmail(is_string($loginValue) ? $loginValue : '');
        if ($user === null) {
            return $this->redirect($this->url->generate('voyti/session-confirm'));
        }

        $twoFactor = UserTwoFactor::forUser($user);
        if (
            !$twoFactor->isEnabled()
            || $twoFactor->getMethod() !== 'webauthn'
            || UserWebauthnCredential::findAllByUserId($user->getIdOrZero()) === []
        ) {
            return $this->redirect($this->url->generate('voyti/session-confirm'));
        }

        $domain = $request->getUri()->getHost();
        $data = [
            'requestOptions' => $this->webauthnService->getGetArgs($user, $domain),
            'formSubmitUrl' => $this->url->generate('voyti/session-confirm'),
            'errorMessage' => $this->translator()->translate(
                'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message',
                category: 'voyti-2fa-webauthn',
            ),
        ];

        return $this->renderFragment('two-factor/_webauthn-confirm', ['data' => $data]);
    }

    public function reauth(ServerRequestInterface $request): ResponseInterface
    {
        /** @var User $user */
        $user = $this->currentUser->getIdentity();

        $twoFactor = UserTwoFactor::forUser($user);
        if (
            !$twoFactor->isEnabled()
            || $twoFactor->getMethod() !== 'webauthn'
            || UserWebauthnCredential::findAllByUserId($user->getIdOrZero()) === []
        ) {
            return $this->redirect($this->url->generate('voyti/user-two-factor'));
        }

        $domain = $request->getUri()->getHost();
        $data = [
            'requestOptions' => $this->webauthnService->getGetArgs($user, $domain),
            'formSubmitUrl' => $this->url->generate('voyti/session-confirm'),
            'errorMessage' => $this->translator()->translate(
                'voyti-2fa-webauthn.view.two_factor_webauthn_confirm.failure_message',
                category: 'voyti-2fa-webauthn',
            ),
        ];

        return $this->renderFragment('two-factor/_webauthn-confirm', ['data' => $data]);
    }

    public function register(ServerRequestInterface $request): ResponseInterface
    {
        /** @var User $user */
        $user = $this->currentUser->getIdentity();

        if (UserTwoFactor::forUser($user)->isEnabled()) {
            return $this->redirect($this->url->generate('voyti/user-two-factor'));
        }

        $payload = $request->getParsedBody();
        $payload = is_array($payload) ? $payload : [];
        $domain = $request->getUri()->getHost();

        if ($this->webauthnService->register($user, $payload, $domain)) {
            $twoFactor = UserTwoFactor::forUser($user);
            $twoFactor->setMethod('webauthn');
            $twoFactor->setEnabled(true);
            $twoFactor->save();

            return $this->renderBackupCodes($this->backupCodeService->generate($user));
        }

        return $this->renderTwoFactorIndex(
            $user,
            $this->twoFactorMethods->get('webauthn'),
            errors: ['webauthn' => [$this->webauthnService->getErrorMessage()]],
        );
    }

    public function settings(ServerRequestInterface $request): ResponseInterface
    {
        /** @var User $user */
        $user = $this->currentUser->getIdentity();

        if (UserTwoFactor::forUser($user)->isEnabled()) {
            return $this->redirect($this->url->generate('voyti/user-two-factor'));
        }

        $domain = $request->getUri()->getHost();
        $data = $this->createSetupData($user, $domain);

        if (strtolower($request->getHeaderLine('X-Requested-With')) === 'xmlhttprequest') {
            return $this->renderFragment('two-factor/_webauthn', ['data' => $data]);
        }

        return $this->renderTwoFactorIndex(
            $user,
            $this->twoFactorMethods->get('webauthn'),
            preloadedFragmentHtml: (string) $this->renderFragment('two-factor/_webauthn', ['data' => $data])->getBody(),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function createSetupData(User $user, string $domain = ''): array
    {
        return [
            'requestOptions' => $this->webauthnService->getCreateArgs($user, $domain),
            'registerUrl' => $this->url->generate('voyti/user-two-factor-webauthn-register'),
            'errorMessage' => $this->translator()->translate(
                'voyti-2fa-webauthn.view.two_factor_webauthn.register_failed',
                category: 'voyti-2fa-webauthn',
            ),
        ];
    }

    /**
     * @param list<string> $codes
     */
    private function renderBackupCodes(array $codes): ResponseInterface
    {
        return $this->renderView('two-factor/backup-codes', [
            'coreViews' => $this->resolveViewPath('shared/_menu'),
            'data' => [
                'menu' => MenuView::account($this->config, $this->url, $this->translator()),
                'codes' => $codes,
                'continueUrl' => $this->url->generate('voyti/user-two-factor'),
            ],
        ]);
    }

    /**
     * @param array<string, list<string>> $errors
     */
    private function renderTwoFactorIndex(
        User $user,
        TwoFactorMethodInterface $method,
        array $errors = [],
        ?string $preloadedFragmentHtml = null,
    ): ResponseInterface {
        return $this->renderView('two-factor/index', [
            'coreViews' => $this->resolveViewPath('shared/_menu'),
            /** @infection-ignore-all The index template only uses `$form` in the enabled-user branch (disable form); this screen only ever shows non-enabled users, so the value is unobservable here. */
            'form' => new TwoFactorCodeForm($this->translator, $method->getName()),
            'data' => IndexView::create(
                UserTwoFactor::forUser($user)->isEnabled(),
                $method,
                $errors,
                /** @infection-ignore-all codeDelivered only affects the disable-confirmation flow, which needs an enabled user; this setup screen only ever shows non-enabled users, so the value is unobservable. */
                false,
                $this->backupCodeService->hasUnused($user),
                $preloadedFragmentHtml,
                $this->twoFactorMethods->getAvailable(),
                $this->config,
                $this->url,
                $this->translator(),
            ),
        ]);
    }
}
