<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support;

use stdClass;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use Yiisoft\Session\SessionInterface;

trait WebauthnCredentialFactoryTrait
{
    public const string CREDENTIAL_ID_BINARY = 'credential-id-binary';
    public const string CREDENTIAL_ID_NOCOUNTER = 'credential-id-nocounter';
    public const string ERROR_EXPIRED = 'The security key check has expired. Please try again.';
    public const string ERROR_NOT_FOUND = 'No matching security key was found for this account.';
    public const string ERROR_VERIFICATION = 'The security key could not be verified. Please try again.';
    public const string SESSION_KEY_CONFIRM_CHALLENGE = 'voyti-2fa-webauthn-confirm-challenge';
    public const string SESSION_KEY_REGISTER_CHALLENGE = 'voyti-2fa-webauthn-register-challenge';

    protected function createCredential(User $user, string $credentialId): void
    {
        $credential = new UserWebauthnCredential();
        $credential->setUserId((int) $user->getId());
        $credential->setCredentialId($credentialId);
        $credential->setPublicKey('-----BEGIN PUBLIC KEY-----');
        $credential->setSignCount(0);
        $credential->setCreatedAt(1000);
        $credential->setUpdatedAt(1000);
        $credential->save();
    }

    protected function sessionWithConfirmChallenge(): SessionInterface
    {
        $session = new FakeSession();
        $session->set(self::SESSION_KEY_CONFIRM_CHALLENGE, 'challenge');

        return $session;
    }

    protected function sessionWithRegisterChallenge(): SessionInterface
    {
        $session = new FakeSession();
        $session->set(self::SESSION_KEY_REGISTER_CHALLENGE, 'challenge');

        return $session;
    }

    protected function validCreateResult(): stdClass
    {
        $result = new stdClass();
        $result->credentialId = self::CREDENTIAL_ID_BINARY;
        $result->credentialPublicKey = '-----BEGIN PUBLIC KEY-----';
        $result->signatureCounter = 3;
        $result->AAGUID = 'aaguid-hex';
        $result->isBackupEligible = true;
        $result->isBackedUp = true;

        return $result;
    }
}
