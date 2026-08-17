<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Service;

use Closure;
use ReportUri\Passkeys\WebAuthn;
use ReportUri\Passkeys\WebAuthnException;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use YiiRocks\Voyti\TwoFactor\Webauthn\Service\WebauthnService;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\FakeSession;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\StubWebAuthn;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\UserFactoryTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\WebauthnCredentialFactoryTrait;
use Yiisoft\Session\SessionInterface;

final class WebauthnServiceTest extends DatabaseTestCase
{
    use UserFactoryTrait;
    use WebauthnCredentialFactoryTrait;

    public function testDeleteAllCredentials(): void
    {
        $user = $this->createUser(username: 'wa_delete', email: 'wa_delete@example.com');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        $this->createService(new FakeSession())->deleteAllCredentials($user);

        self::assertSame([], UserWebauthnCredential::findAllByUserId((int) $user->getId()));
    }

    public function testGetCreateArgsStoresChallenge(): void
    {
        $user = $this->createUser(username: 'wa_create', email: 'wa_create@example.com');

        $session = new FakeSession();
        $service = $this->createService($session);

        $args = $service->getCreateArgs($user);

        self::assertSame('localhost', $args['publicKey']['rp']['id']);
        self::assertSame('public-key', $args['publicKey']['pubKeyCredParams'][0]['type']);
        self::assertSame(60000, $args['publicKey']['timeout']);
        self::assertSame($user->getUsername(), $args['publicKey']['user']['name']);
        // The user handle is a stable per-user hash (prefix + id), base64url-encoded in the args.
        self::assertSame(
            hash('sha256', 'yiirocks/voyti-2fa-webauthn:' . $user->getIdOrZero(), true),
            base64_decode(strtr((string) $args['publicKey']['user']['id'], '-_', '+/')),
        );
        // The ceremony flags: user verification required, resident key not required.
        self::assertSame('required', $args['publicKey']['authenticatorSelection']['userVerification']);
        self::assertArrayNotHasKey('requireResidentKey', $args['publicKey']['authenticatorSelection']);
        self::assertSame('', $service->getErrorMessage());
        self::assertIsString($session->get(self::SESSION_KEY_REGISTER_CHALLENGE));
        self::assertNotSame('', $session->get(self::SESSION_KEY_REGISTER_CHALLENGE));
    }

    public function testGetGetArgsRestrictsToEnrolledCredentials(): void
    {
        $user = $this->createUser(username: 'wa_getargs', email: 'wa_getargs@example.com');
        $this->createCredential($user, self::CREDENTIAL_ID_BINARY);

        $session = new FakeSession();
        $service = $this->createService($session);

        $args = $service->getGetArgs($user);

        self::assertSame(60000, $args['publicKey']['timeout']);
        self::assertSame('required', $args['publicKey']['userVerification']);
        self::assertCount(1, $args['publicKey']['allowCredentials']);
        self::assertSame('public-key', $args['publicKey']['allowCredentials'][0]['type']);
        self::assertIsString($args['publicKey']['allowCredentials'][0]['id']);
        // All transports are advertised (every allow* flag is enabled).
        self::assertSame(
            ['usb', 'nfc', 'ble', 'hybrid', 'internal'],
            $args['publicKey']['allowCredentials'][0]['transports'],
        );
        self::assertIsString($session->get(self::SESSION_KEY_CONFIRM_CHALLENGE));

        // Scenario 2: a user without credentials gets no allowCredentials restriction at all
        $emptyUser = $this->createUser(username: 'wa_getargs_empty', email: 'wa_getargs_empty@example.com');
        $emptySession = new FakeSession();
        $emptyArgs = $this->createService($emptySession)->getGetArgs($emptyUser);
        self::assertArrayNotHasKey('allowCredentials', $emptyArgs['publicKey']);
    }

    public function testRegister(): void
    {
        $user = $this->createUser(username: 'wa_register', email: 'wa_register@example.com');

        // Scenario 1: successful registration persists the credential and clears the challenge
        $webauthn = new StubWebAuthn();
        $webauthn->createResult = $this->validCreateResult();
        $session = $this->sessionWithRegisterChallenge();
        $service = $this->createService($session, fn() => $webauthn);

        self::assertTrue($service->register($user, [
            'clientDataJSON' => base64_encode('{}'),
            'attestationObject' => base64_encode('raw'),
        ]));
        self::assertSame('', $service->getErrorMessage());
        self::assertArrayNotHasKey(self::SESSION_KEY_REGISTER_CHALLENGE, $session->all());
        // The base64 inputs are decoded before reaching the verifier, with user verification required.
        self::assertSame('{}', $webauthn->lastCreateClientDataJSON);
        self::assertSame('raw', $webauthn->lastCreateAttestationObject);
        self::assertTrue($webauthn->lastCreateRequireUserVerification);

        $stored = UserWebauthnCredential::findByUserIdAndCredentialId((int) $user->getId(), base64_encode(self::CREDENTIAL_ID_BINARY));
        self::assertNotNull($stored);
        self::assertSame('-----BEGIN PUBLIC KEY-----', $stored->getPublicKey());
        self::assertSame(3, $stored->getSignCount());
        self::assertSame(bin2hex('aaguid-hex'), $stored->getAaguid());
        self::assertTrue($stored->isBackupEligible());
        self::assertTrue($stored->isBackedUp());
        // Timestamps come from the injected clock (@1000000000).
        self::assertSame(1000000000, $stored->getCreatedAt());
        self::assertSame(1000000000, $stored->getUpdatedAt());

        // Scenario 2: a result without a signature counter stores zero (the ?? 0 default).
        $userNoCounter = $this->createUser(username: 'wa_register_nc', email: 'wa_register_nc@example.com');
        $webauthnNoCounter = new StubWebAuthn();
        $noCounterResult = $this->validCreateResult();
        $noCounterResult->credentialId = self::CREDENTIAL_ID_NOCOUNTER;
        $noCounterResult->signatureCounter = null;
        $webauthnNoCounter->createResult = $noCounterResult;
        $sessionNoCounter = $this->sessionWithRegisterChallenge();
        self::assertTrue($this->createService($sessionNoCounter, fn() => $webauthnNoCounter)->register($userNoCounter, [
            'clientDataJSON' => base64_encode('{}'),
            'attestationObject' => base64_encode('raw'),
        ]));
        $storedNoCounter = UserWebauthnCredential::findByUserIdAndCredentialId((int) $userNoCounter->getId(), base64_encode(self::CREDENTIAL_ID_NOCOUNTER));
        self::assertNotNull($storedNoCounter);
        self::assertSame(0, $storedNoCounter->getSignCount());

        // Scenario 3: missing challenge fails with the expiration error
        $service2 = $this->createService(new FakeSession());
        self::assertFalse($service2->register($user, []));
        self::assertSame(self::ERROR_EXPIRED, $service2->getErrorMessage());

        // Scenario 3: a verification exception fails with the generic verification error
        $webauthn3 = new StubWebAuthn();
        $webauthn3->createException = new WebAuthnException('boom');
        $session3 = $this->sessionWithRegisterChallenge();
        $service3 = $this->createService($session3, fn() => $webauthn3);
        self::assertFalse($service3->register($user, []));
        self::assertSame(self::ERROR_VERIFICATION, $service3->getErrorMessage());
    }

    public function testVerify(): void
    {
        $user = $this->createUser(username: 'wa_verify', email: 'wa_verify@example.com');
        $this->createCredential($user, base64_encode(self::CREDENTIAL_ID_BINARY));

        // Scenario 1: a valid assertion updates the sign counter and clears the challenge
        $webauthn = new StubWebAuthn();
        $webauthn->signatureCounter = 9;
        $session = $this->sessionWithConfirmChallenge();
        $service = $this->createService($session, fn() => $webauthn);

        self::assertTrue($service->verify($user, [
            'id' => base64_encode(self::CREDENTIAL_ID_BINARY),
            'clientDataJSON' => base64_encode('{}'),
            'authenticatorData' => base64_encode('auth'),
            'signature' => base64_encode('sig'),
        ]));
        self::assertSame('', $service->getErrorMessage());
        self::assertTrue($webauthn->processGetCalled);
        self::assertTrue($webauthn->lastGetRequireUserVerification);
        self::assertSame('{}', $webauthn->lastGetClientDataJSON);
        self::assertArrayNotHasKey(self::SESSION_KEY_CONFIRM_CHALLENGE, $session->all());

        $reloaded = UserWebauthnCredential::findByUserIdAndCredentialId((int) $user->getId(), base64_encode(self::CREDENTIAL_ID_BINARY));
        self::assertSame(9, $reloaded->getSignCount());
        // The counter update stamps updatedAt from the injected clock (@1000000000).
        self::assertSame(1000000000, $reloaded->getUpdatedAt());

        // Scenario 2: a valid assertion with no signature counter keeps the stored counter
        $user2 = $this->createUser(username: 'wa_verify_nocounter', email: 'wa_verify_nocounter@example.com');
        $this->createCredential($user2, base64_encode(self::CREDENTIAL_ID_NOCOUNTER));
        $webauthn2 = new StubWebAuthn();
        $webauthn2->signatureCounter = null;
        $session2 = new FakeSession();
        $session2->set(self::SESSION_KEY_CONFIRM_CHALLENGE, 'challenge');
        $service2 = $this->createService($session2, fn() => $webauthn2);

        self::assertTrue($service2->verify($user2, ['id' => base64_encode(self::CREDENTIAL_ID_NOCOUNTER)]));

        $reloaded2 = UserWebauthnCredential::findByUserIdAndCredentialId((int) $user2->getId(), base64_encode(self::CREDENTIAL_ID_NOCOUNTER));
        self::assertSame(0, $reloaded2->getSignCount());

        // Scenario 3: missing challenge fails with the expiration error
        $service3 = $this->createService(new FakeSession());
        self::assertFalse($service3->verify($user, ['id' => base64_encode(self::CREDENTIAL_ID_BINARY)]));
        self::assertSame(self::ERROR_EXPIRED, $service3->getErrorMessage());

        // Scenario 4: a credential that is not enrolled fails with the not-found error
        $session4 = $this->sessionWithConfirmChallenge();
        $service4 = $this->createService($session4);
        self::assertFalse($service4->verify($user, ['id' => base64_encode('unknown-credential')]));
        self::assertSame(self::ERROR_NOT_FOUND, $service4->getErrorMessage());

        // Scenario 5: a verification exception fails with the generic verification error
        $webauthn5 = new StubWebAuthn();
        $webauthn5->getException = new WebAuthnException('boom');
        $session5 = $this->sessionWithConfirmChallenge();
        $service5 = $this->createService($session5, fn() => $webauthn5);
        self::assertFalse($service5->verify($user, ['id' => base64_encode(self::CREDENTIAL_ID_BINARY)]));
        self::assertSame(self::ERROR_VERIFICATION, $service5->getErrorMessage());
    }

    private function createService(SessionInterface $session, ?callable $webauthnFactory = null): WebauthnService
    {
        $factory = $webauthnFactory ?? static fn(string $domain): WebAuthn => new StubWebAuthn();

        return new WebauthnService(
            $session,
            $this->createTranslator(),
            $this->createTestClock(),
            Closure::fromCallable($factory),
        );
    }
}
