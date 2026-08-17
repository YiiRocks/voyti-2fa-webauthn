<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Controller;

use Closure;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use Psr\Clock\ClockInterface;
use ReportUri\Passkeys\WebAuthnException;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Model\UserTwoFactor;
use YiiRocks\Voyti\TwoFactor\Webauthn\Controller\WebauthnController;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\CurrentUserTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\StubWebAuthn;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\TestContainerTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\UserFactoryTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\VoytiConfigFactory;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\WebauthnCredentialFactoryTrait;
use YiiRocks\Voyti\VoytiConfig;
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\TranslatorInterface;
use Yiisoft\User\CurrentUser;

#[AllowMockObjectsWithoutExpectations]
final class WebauthnControllerTest extends DatabaseTestCase
{
    use CurrentUserTrait;
    use TestContainerTrait;
    use UserFactoryTrait;
    use WebauthnCredentialFactoryTrait;

    private CurrentUser $currentUser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->currentUser = $this->createCurrentUser();
    }

    public function testConfirm(): void
    {
        $user = $this->createUser(username: 'wa_confirm', email: 'wa_confirm@example.com');
        $this->createUserTwoFactor((int) ($user->getId() ?? 0), enabled: true, method: 'webauthn');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        $container = $this->createTestContainer([CurrentUser::class => $this->currentUser]);
        $container->get(SessionInterface::class)->set('credentials', ['login' => 'wa_confirm']);

        $html = (string) $container->get(WebauthnController::class)->confirm(new ServerRequest('GET', '/'))->getBody();

        // The fragment locates its host generically (shared with the settings re-auth flow) and
        // falls back to the login-confirm route as its POST target.
        self::assertStringContainsString('data-voyti-2fa-assertion-host', $html);
        self::assertStringContainsString('session-confirm', $html);
        self::assertStringContainsString("Confirm it's you", $html);
    }

    public function testConfirmRedirectsWhenNotApplicable(): void
    {
        // Each user isolates a single failing condition (the others pass), so every guard clause is
        // independently exercised.
        // Disabled only: webauthn method + an enrolled key, but 2FA not enabled.
        $disabled = $this->createUser(username: 'wa_disabled', email: 'wa_disabled@example.com');
        $this->createUserTwoFactor((int) ($disabled->getId() ?? 0), enabled: false, method: 'webauthn');
        $this->createCredential($disabled, base64_encode('cred-disabled'));
        // Wrong method only: enabled + an enrolled key, but method is totp.
        $totp = $this->createUser(username: 'wa_totp', email: 'wa_totp@example.com');
        $this->createUserTwoFactor((int) ($totp->getId() ?? 0), enabled: true, method: 'totp');
        $this->createCredential($totp, base64_encode('cred-totp'));
        // No key only: enabled + webauthn method, but no enrolled key.
        $nokey = $this->createUser(username: 'wa_nokey', email: 'wa_nokey@example.com');
        $this->createUserTwoFactor((int) ($nokey->getId() ?? 0), enabled: true, method: 'webauthn');

        $container = $this->createTestContainer([CurrentUser::class => $this->currentUser]);
        $session = $container->get(SessionInterface::class);
        $controller = $container->get(WebauthnController::class);

        // Scenario 1: no pending-login details in the session
        $session->clear();
        self::assertSame(302, $controller->confirm(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 2: the login does not resolve to a user
        $session->set('credentials', ['login' => 'ghost']);
        self::assertSame(302, $controller->confirm(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 3: 2FA disabled (sole failing condition)
        $session->set('credentials', ['login' => 'wa_disabled']);
        self::assertSame(302, $controller->confirm(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 4: a different 2FA method (sole failing condition)
        $session->set('credentials', ['login' => 'wa_totp']);
        self::assertSame(302, $controller->confirm(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 5: no enrolled security key (sole failing condition)
        $session->set('credentials', ['login' => 'wa_nokey']);
        self::assertSame(302, $controller->confirm(new ServerRequest('GET', '/'))->getStatusCode());
    }

    public function testReauth(): void
    {
        $user = $this->createUser(username: 'wa_reauth', email: 'wa_reauth@example.com');
        $this->createUserTwoFactor((int) ($user->getId() ?? 0), enabled: true, method: 'webauthn');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));
        $this->currentUser->login($user);

        $container = $this->createTestContainer([CurrentUser::class => $this->currentUser]);

        $html = (string) $container->get(WebauthnController::class)->reauth(new ServerRequest('GET', '/'))->getBody();

        // The settings page supplies the POST target on the host container; the fragment just runs
        // the assertion ceremony against a fresh challenge.
        self::assertStringContainsString('data-voyti-2fa-assertion-host', $html);
        self::assertStringContainsString("Confirm it's you", $html);
    }

    public function testReauthRedirectsWhenNotApplicable(): void
    {
        // Each user isolates a single failing condition (the others pass), so every guard clause is
        // independently exercised.
        // Disabled only: webauthn method + an enrolled key, but 2FA not enabled.
        $disabled = $this->createUser(username: 'wa_re_disabled', email: 'wa_re_disabled@example.com');
        $this->createUserTwoFactor((int) ($disabled->getId() ?? 0), enabled: false, method: 'webauthn');
        $this->createCredential($disabled, base64_encode('cred-re-disabled'));
        // Wrong method only: enabled + an enrolled key, but method is totp.
        $totp = $this->createUser(username: 'wa_re_totp', email: 'wa_re_totp@example.com');
        $this->createUserTwoFactor((int) ($totp->getId() ?? 0), enabled: true, method: 'totp');
        $this->createCredential($totp, base64_encode('cred-re-totp'));
        // No key only: enabled + webauthn method, but no enrolled key.
        $nokey = $this->createUser(username: 'wa_re_nokey', email: 'wa_re_nokey@example.com');
        $this->createUserTwoFactor((int) ($nokey->getId() ?? 0), enabled: true, method: 'webauthn');

        $container = $this->createTestContainer([CurrentUser::class => $this->currentUser]);
        $controller = $container->get(WebauthnController::class);

        // Scenario 1: 2FA disabled (sole failing condition)
        $this->currentUser->login($disabled);
        self::assertSame(302, $controller->reauth(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 2: a different 2FA method (sole failing condition)
        $this->currentUser->login($totp);
        self::assertSame(302, $controller->reauth(new ServerRequest('GET', '/'))->getStatusCode());

        // Scenario 3: no enrolled security key (sole failing condition)
        $this->currentUser->login($nokey);
        self::assertSame(302, $controller->reauth(new ServerRequest('GET', '/'))->getStatusCode());
    }

    public function testRegister(): void
    {
        $user = $this->createUser(username: 'wa_register', email: 'wa_register@example.com');
        $this->currentUser->login($user);

        // Scenario 1: a successful ceremony enables 2FA, persists the key and shows backup codes
        $stub = new StubWebAuthn();
        $stub->createResult = $this->validCreateResult();
        $factory = static fn(string $domain): StubWebAuthn => $stub;
        $container = $this->createTestContainer([
            CurrentUser::class => $this->currentUser,
            WebauthnService::class => fn(SessionInterface $session, TranslatorInterface $translator, ClockInterface $clock) => new WebauthnService($session, $translator, $clock, Closure::fromCallable($factory)),
        ]);
        $container->get(SessionInterface::class)->set(self::SESSION_KEY_REGISTER_CHALLENGE, 'challenge');

        $result = $container->get(WebauthnController::class)->register(
            (new ServerRequest('POST', '/'))->withParsedBody([
                'clientDataJSON' => base64_encode('{}'),
                'attestationObject' => base64_encode('raw'),
            ]),
        );

        self::assertSame(200, $result->getStatusCode());
        // Assert on text unique to the backup-codes page (not the enabled index's "Regenerate
        // Backup Codes"), so falling through to the index instead is caught.
        self::assertStringContainsString('Save these one-time backup codes', (string) $result->getBody());

        $twoFactor = UserTwoFactor::forUser($user);
        self::assertTrue($twoFactor->isEnabled());
        self::assertSame('webauthn', $twoFactor->getMethod());
        self::assertCount(1, UserWebauthnCredential::findAllByUserId((int) $user->getId()));

        // Scenario 2: a failed ceremony re-renders the setup screen with the error. A non-array
        // request body must be coerced to an empty array (not passed through) before the service call.
        $user2 = $this->createUser(username: 'wa_register2', email: 'wa_register2@example.com');
        $this->currentUser->login($user2);
        $stub2 = new StubWebAuthn();
        $stub2->createException = new WebAuthnException('boom');
        $factory2 = static fn(string $domain): StubWebAuthn => $stub2;
        $container2 = $this->createTestContainer([
            CurrentUser::class => $this->currentUser,
            WebauthnService::class => fn(SessionInterface $session, TranslatorInterface $translator, ClockInterface $clock) => new WebauthnService($session, $translator, $clock, Closure::fromCallable($factory2)),
        ]);
        $container2->get(SessionInterface::class)->set(self::SESSION_KEY_REGISTER_CHALLENGE, 'challenge');

        $result2 = $container2->get(WebauthnController::class)->register(new ServerRequest('POST', '/'));

        self::assertSame(200, $result2->getStatusCode());
        self::assertStringContainsString('The security key could not be verified. Please try again.', (string) $result2->getBody());
        self::assertStringContainsString('Security key', (string) $result2->getBody());
    }

    public function testRegisterWhenAlreadyEnabledRedirects(): void
    {
        $user = $this->createUser(username: 'wa_register_enabled', email: 'wa_register_enabled@example.com');
        $this->createUserTwoFactor((int) ($user->getId() ?? 0), enabled: true, method: 'webauthn');
        $this->currentUser->login($user);

        $result = $this->createController()->register(new ServerRequest('POST', '/'));

        self::assertSame(302, $result->getStatusCode());
        self::assertSame('//voyti/user-two-factor', $result->getHeaderLine('Location'));
    }

    public function testSettings(): void
    {
        $user = $this->createUser(username: 'wa_settings', email: 'wa_settings@example.com');
        $this->currentUser->login($user);

        // Scenario 1: a regular request renders the settings page with the fragment preloaded inline
        $html = (string) $this->createController()->settings(new ServerRequest('GET', '/'))->getBody();
        self::assertStringContainsString('Two-Factor Authentication', $html);
        self::assertStringContainsString('Security key', $html);
        self::assertStringContainsString('user-two-factor-webauthn-register', $html);
        self::assertStringContainsString('Register security key', $html);

        // Scenario 2: an AJAX request returns only the setup fragment (no full-page chrome)
        $request = (new ServerRequest('GET', '/'))->withHeader('X-Requested-With', 'XMLHttpRequest');
        $html = (string) $this->createController()->settings($request)->getBody();
        self::assertStringContainsString('user-two-factor-webauthn-register', $html);
        self::assertStringNotContainsString('<h1>', $html);
    }

    public function testSettingsUsesHostViewPathOverride(): void
    {
        $user = $this->createUser(username: 'wa_host_views', email: 'wa_host_views@example.com');
        $this->currentUser->login($user);

        $hostViews = sys_get_temp_dir() . '/voyti-2fa-webauthn-host-views-' . bin2hex(random_bytes(6));
        $indexView = $hostViews . '/two-factor/index.php';
        mkdir(dirname($indexView), 0o777, true);
        file_put_contents($indexView, '<?php echo "HOST_TWO_FACTOR_INDEX_OVERRIDE";');

        try {
            $container = $this->createTestContainer([
                CurrentUser::class => $this->currentUser,
                VoytiConfig::class => VoytiConfigFactory::create(viewPath: $hostViews),
            ]);
            $html = (string) $container->get(WebauthnController::class)->settings(new ServerRequest('GET', '/'))->getBody();
            self::assertStringContainsString('HOST_TWO_FACTOR_INDEX_OVERRIDE', $html);

            // Scenario 2: a viewPath override without the view falls back to voyti-2fa's own view
            mkdir($hostViews . '/empty', 0o777, true);
            $container = $this->createTestContainer([
                CurrentUser::class => $this->currentUser,
                VoytiConfig::class => VoytiConfigFactory::create(viewPath: $hostViews . '/empty'),
            ]);
            $html = (string) $container->get(WebauthnController::class)->settings(new ServerRequest('GET', '/'))->getBody();
            self::assertStringContainsString('Two-Factor Authentication', $html);
            self::assertStringNotContainsString('HOST_TWO_FACTOR_INDEX_OVERRIDE', $html);
        } finally {
            @unlink($indexView);
            @rmdir($hostViews . '/empty');
            @rmdir($hostViews . '/two-factor');
            @rmdir($hostViews);
        }
    }

    public function testSettingsWhenAlreadyEnabledRedirects(): void
    {
        $user = $this->createUser(username: 'wa_enabled', email: 'wa_enabled@example.com');
        $this->createUserTwoFactor((int) ($user->getId() ?? 0), enabled: true, method: 'webauthn');
        $this->currentUser->login($user);

        $result = $this->createController()->settings(new ServerRequest('GET', '/'));

        self::assertSame(302, $result->getStatusCode());
        self::assertSame('//voyti/user-two-factor', $result->getHeaderLine('Location'));
    }

    private function createController(): WebauthnController
    {
        return $this->createTestContainer([
            CurrentUser::class => $this->currentUser,
        ])->get(WebauthnController::class);
    }
}
