<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests;

use Closure;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\FakeSession;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\FakeUrlGenerator;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\StubWebAuthn;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\UserFactoryTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\WebauthnCredentialFactoryTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\WebauthnTwoFactorMethod;
use Yiisoft\Json\Json;
use Yiisoft\Session\SessionInterface;

final class WebauthnTwoFactorMethodTest extends DatabaseTestCase
{
    use UserFactoryTrait;
    use WebauthnCredentialFactoryTrait;

    public function testAuthenticationHooksAreNoOp(): void
    {
        $user = new User();
        $method = $this->createMethod(new StubWebAuthn(), new FakeSession());

        $method->onAuthenticationStepStart($user);

        self::assertSame('', $method->getErrorMessage());
    }

    public function testOnDisableDeletesAllCredentials(): void
    {
        $user = $this->createUser(username: 'wa_disable', email: 'wa_disable@example.com');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        $this->createMethod(new StubWebAuthn(), new FakeSession())->onDisable($user);

        self::assertSame([], UserWebauthnCredential::findAllByUserId((int) $user->getId()));
    }

    public function testStaticIdentity(): void
    {
        $method = $this->createMethod(new StubWebAuthn(), new FakeSession());

        self::assertSame('webauthn', $method->getName());
        self::assertTrue($method->isAvailable());
        self::assertFalse($method->isCodeBased());
        self::assertFalse($method->requiresCodeDelivery());
        self::assertSame('//voyti/user-two-factor-webauthn-confirm', $method->getConfirmFragmentUrl(new FakeUrlGenerator()));
        self::assertSame('//voyti/user-two-factor-webauthn', $method->getSettingsUrl(new FakeUrlGenerator()));
        self::assertSame('Security key', $method->getButtonLabel($this->createTranslator()));
        self::assertSame('Security key', $method->getEnabledWithMethodName($this->createTranslator()));
        self::assertSame('', $method->getErrorMessage());
    }

    public function testVerify(): void
    {
        $user = $this->createUser(username: 'wa_method', email: 'wa_method@example.com');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        $webauthn = new StubWebAuthn();
        $session = $this->sessionWithConfirmChallenge();
        $method = $this->createMethod($webauthn, $session);

        // Scenario 1: a JSON payload is decoded and passed to the service
        self::assertTrue($method->verify($user, [
            'payload' => Json::encode([
                'id' => base64_encode(self::CREDENTIAL_ID_BINARY),
                'signature' => base64_encode('sig'),
            ]),
        ]));
        self::assertTrue($webauthn->processGetCalled);
        self::assertSame('', $method->getErrorMessage());

        // Scenario 2: invalid JSON falls back to an empty payload and fails
        self::assertFalse($method->verify($user, ['payload' => 'not-json']));
        self::assertSame('The security key check has expired. Please try again.', $method->getErrorMessage());

        // Scenario 3: an empty payload fails
        self::assertFalse($method->verify($user, ['payload' => '']));

        // Scenario 4: JSON that decodes to a non-array (e.g. an int) fails
        self::assertFalse($method->verify($user, ['payload' => Json::encode(123)]));

        // Scenario 5: no payload key at all fails
        self::assertFalse($method->verify($user, []));
    }

    public function testVerifyUsesRequestDomainForRelyingParty(): void
    {
        $user = $this->createUser(username: 'wa_domain', email: 'wa_domain@example.com');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        $webauthn = new StubWebAuthn();
        $session = new FakeSession();
        $session->set('voyti-2fa-webauthn-confirm-challenge', 'challenge');

        $domains = [];
        $factory = static function (string $domain) use ($webauthn, &$domains): StubWebAuthn {
            $domains[] = $domain;

            return $webauthn;
        };
        $method = new WebauthnTwoFactorMethod(
            new WebauthnService($session, $this->createTranslator(), $this->createTestClock(), Closure::fromCallable($factory)),
        );

        self::assertTrue($method->verify($user, [
            'payload' => Json::encode([
                'id' => base64_encode(self::CREDENTIAL_ID_BINARY),
                'signature' => base64_encode('sig'),
            ]),
            'domain' => 'example.com',
        ]));
        // The request host is threaded through as the relying-party id the ceremony is built with;
        // without it the assertion's rpIdHash never matches and login always fails.
        self::assertContains('example.com', $domains);
    }

    private function createMethod(StubWebAuthn $webauthn, SessionInterface $session): WebauthnTwoFactorMethod
    {
        $factory = static fn(string $domain): StubWebAuthn => $webauthn;
        return new WebauthnTwoFactorMethod(
            new WebauthnService($session, $this->createTranslator(), $this->createTestClock(), Closure::fromCallable($factory)),
        );
    }
}
