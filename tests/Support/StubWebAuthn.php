<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support;

use ReportUri\Passkeys\WebAuthn;
use ReportUri\Passkeys\WebAuthnException;
use stdClass;

/**
 * Test double for the WebAuthn server library: real constructor (so `getCreateArgs()`/`getGetArgs()`
 * and challenge generation work exactly as in production) with the verification entry points stubbed,
 * so tests can simulate successful and failed ceremonies deterministically.
 */
final class StubWebAuthn extends WebAuthn
{
    public ?WebAuthnException $createException = null;
    public ?stdClass $createResult = null;
    public ?WebAuthnException $getException = null;
    public mixed $lastCreateAttestationObject = null;
    public mixed $lastCreateClientDataJSON = null;
    public bool $lastCreateRequireUserVerification = false;
    public mixed $lastGetClientDataJSON = null;
    public bool $lastGetRequireUserVerification = false;
    public bool $processGetCalled = false;
    public ?int $signatureCounter = 7;

    public function __construct()
    {
        parent::__construct('Voyti Test', 'localhost', true);
    }

    public function getSignatureCounter(): ?int
    {
        return $this->signatureCounter;
    }

    public function processCreate(
        mixed $clientDataJSON,
        mixed $attestationObject,
        mixed $challenge,
        mixed $requireUserVerification = false,
        mixed $requireUserPresent = true,
    ): mixed {
        $this->lastCreateClientDataJSON = $clientDataJSON;
        $this->lastCreateAttestationObject = $attestationObject;
        $this->lastCreateRequireUserVerification = $requireUserVerification;

        if ($this->createException !== null) {
            throw $this->createException;
        }

        return $this->createResult;
    }

    public function processGet(
        mixed $clientDataJSON,
        mixed $authenticatorData,
        mixed $signature,
        mixed $credentialPublicKey,
        mixed $challenge,
        mixed $prevSignatureCnt = null,
        mixed $requireUserVerification = false,
        mixed $requireUserPresent = true,
    ): mixed {
        $this->processGetCalled = true;
        $this->lastGetClientDataJSON = $clientDataJSON;
        $this->lastGetRequireUserVerification = $requireUserVerification;

        if ($this->getException !== null) {
            throw $this->getException;
        }

        return true;
    }
}
