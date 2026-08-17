<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\Service;

use Closure;
use Psr\Clock\ClockInterface;
use ReportUri\Passkeys\WebAuthn;
use ReportUri\Passkeys\WebAuthnException;
use stdClass;
use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use Yiisoft\Json\Json;
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\TranslatorInterface;

/**
 * Drives WebAuthn registration and assertion ceremonies for the configured relying party: builds
 * the creation/request options the browser passes to `navigator.credentials.create()`/`.get()`
 * (persisting each ceremony's challenge in the session), verifies the browser's attestation/
 * assertion against the {@see WebAuthn} server library, and stores/updates the user's enrolled
 * public-key credentials. All errors surface through {@see self::getErrorMessage()}.
 */
final class WebauthnService
{
    private const string SESSION_KEY_CONFIRM_CHALLENGE = 'voyti-2fa-webauthn-confirm-challenge';
    private const string SESSION_KEY_REGISTER_CHALLENGE = 'voyti-2fa-webauthn-register-challenge';

    private ?string $errorMessage = null;

    /**
     * @param Closure(string): WebAuthn $webauthnFactory Builds a relying-party-scoped WebAuthn
     *        server for a given request domain (wired in `config/di.php`).
     */
    public function __construct(
        private readonly SessionInterface $session,
        private readonly TranslatorInterface $translator,
        private readonly ClockInterface $clock,
        private readonly Closure $webauthnFactory,
    ) {}

    /**
     * Removes every enrolled credential (used when two-factor authentication is disabled).
     */
    public function deleteAllCredentials(User $user): void
    {
        UserWebauthnCredential::deleteAllByUserId($user->getIdOrZero());
    }

    /**
     * Builds the `publicKey` options for a `navigator.credentials.create()` call and stores the
     * ceremony challenge in the session, consumed by {@see self::register()}.
     *
     * @return array<string, mixed>
     */
    public function getCreateArgs(User $user, string $domain = ''): array
    {
        $webauthn = $this->createWebAuthn($domain);

        /** @var array<string, mixed> $createArgs */
        $createArgs = Json::decode(Json::encode($webauthn->getCreateArgs(
            $this->userHandle($user),
            $user->getUsername(),
            $user->getUsername(),
            60,
            false,
            true,
        )));

        $this->session->set(self::SESSION_KEY_REGISTER_CHALLENGE, $webauthn->getChallenge()->getBinaryString());

        /** @infection-ignore-all The decoded args are a single-key {publicKey: ...} array, so an array_slice to its first element is identical. */
        return $createArgs;
    }

    public function getErrorMessage(): string
    {
        return $this->errorMessage ?? '';
    }

    /**
     * Builds the `publicKey` options for a `navigator.credentials.get()` call restricted to the
     * user's enrolled credentials, storing the ceremony challenge for {@see self::verify()}.
     *
     * @return array<string, mixed>
     */
    public function getGetArgs(User $user, string $domain = ''): array
    {
        $webauthn = $this->createWebAuthn($domain);
        $credentialIds = [];
        foreach (UserWebauthnCredential::findAllByUserId($user->getIdOrZero()) as $credential) {
            $credentialIds[] = base64_decode($credential->getCredentialId());
        }

        /** @var array<string, mixed> $getArgs */
        $getArgs = Json::decode(Json::encode($webauthn->getGetArgs($credentialIds, 60, true, true, true, true, true, true)));

        $this->session->set(self::SESSION_KEY_CONFIRM_CHALLENGE, $webauthn->getChallenge()->getBinaryString());

        /** @infection-ignore-all The decoded args are a single-key {publicKey: ...} array, so an array_slice to its first element is identical. */
        return $getArgs;
    }

    /**
     * Verifies a registration attestation and persists the new credential.
     *
     * @param array<array-key, mixed> $data expected keys: `clientDataJSON`, `attestationObject`
     */
    public function register(User $user, array $data, string $domain = ''): bool
    {
        $webauthn = $this->createWebAuthn($domain);
        $challenge = $this->session->get(self::SESSION_KEY_REGISTER_CHALLENGE);
        if (!is_string($challenge) || $challenge === '') {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.missing_challenge');
            return false;
        }

        try {
            /** @var stdClass $result */
            $result = $webauthn->processCreate(
                $this->decode($data['clientDataJSON'] ?? null),
                $this->decode($data['attestationObject'] ?? null),
                $challenge,
                true,
            );
        } catch (WebAuthnException) {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.verification_failed');
            return false;
        }

        $this->session->remove(self::SESSION_KEY_REGISTER_CHALLENGE);

        $credential = new UserWebauthnCredential();
        $credential->setUserId($user->getIdOrZero());
        $credential->setCredentialId(base64_encode((string) $result->credentialId));
        $credential->setPublicKey((string) $result->credentialPublicKey);
        $credential->setSignCount((int) ($result->signatureCounter ?? 0));
        $credential->setAaguid(bin2hex((string) $result->AAGUID));
        $credential->setBackupEligible((bool) $result->isBackupEligible);
        $credential->setBackedUp((bool) $result->isBackedUp);
        $now = $this->clock->now()->getTimestamp();
        $credential->setCreatedAt($now);
        $credential->setUpdatedAt($now);
        $credential->save();

        $this->errorMessage = null;

        return true;
    }

    /**
     * Verifies a login assertion against the user's stored credential and updates its sign counter.
     *
     * @param array<array-key, mixed> $data expected keys: `id`, `clientDataJSON`, `authenticatorData`,
     *        `signature`
     */
    public function verify(User $user, array $data, string $domain = ''): bool
    {
        $webauthn = $this->createWebAuthn($domain);
        $challenge = $this->session->get(self::SESSION_KEY_CONFIRM_CHALLENGE);
        if (!is_string($challenge) || $challenge === '') {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.missing_challenge');
            return false;
        }

        $id = base64_decode((string) ($data['id'] ?? ''));
        $credential = UserWebauthnCredential::findByUserIdAndCredentialId($user->getIdOrZero(), base64_encode($id));
        if ($credential === null) {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.credential_not_found');
            return false;
        }

        try {
            $webauthn->processGet(
                $this->decode($data['clientDataJSON'] ?? null),
                $this->decode($data['authenticatorData'] ?? null),
                $this->decode($data['signature'] ?? null),
                $credential->getPublicKey(),
                $challenge,
                $credential->getSignCount(),
                true,
            );
        } catch (WebAuthnException) {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.verification_failed');
            return false;
        }

        $this->session->remove(self::SESSION_KEY_CONFIRM_CHALLENGE);

        $newCounter = $webauthn->getSignatureCounter();
        if ($newCounter !== null) {
            $credential->setSignCount($newCounter);
            $credential->setUpdatedAt($this->clock->now()->getTimestamp());
            $credential->save();
        }

        $this->errorMessage = null;

        return true;
    }

    private function createWebAuthn(string $domain): WebAuthn
    {
        return ($this->webauthnFactory)($domain);
    }

    /**
     * Decodes a base64 value posted by the browser, returning an empty string when absent or invalid
     * (the library then rejects the ceremony with a verification error).
     */
    private function decode(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            return '';
        }

        $decoded = base64_decode($value, true);

        return $decoded === false ? '' : $decoded;
    }

    private function translateError(string $key): string
    {
        return $this->translator->translate($key, category: 'voyti-2fa-webauthn');
    }

    /**
     * Stable per-user binary handle for the `user.id` member of the creation options; not sensitive
     * (the WebAuthn spec treats it as a plain identifier), just deterministic across ceremonies.
     */
    private function userHandle(User $user): string
    {
        return hash('sha256', 'yiirocks/voyti-2fa-webauthn:' . $user->getIdOrZero(), true);
    }
}
