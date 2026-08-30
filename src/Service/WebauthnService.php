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
use Yiisoft\Session\SessionInterface;
use Yiisoft\Translator\TranslatorInterface;

/**
 * Drives WebAuthn registration and login ceremonies for the configured relying party, each a pair
 * of methods: {@see self::getCreateArgs()}/{@see self::register()} for registration (the
 * `navigator.credentials.create()` side), {@see self::getGetArgs()}/{@see self::verify()} for
 * login (the `navigator.credentials.get()` side). Builds each ceremony's options (persisting its
 * challenge in the session), verifies the browser's response against the {@see WebAuthn} server
 * library, and stores/updates the user's enrolled public-key credentials. All errors surface
 * through {@see self::getErrorMessage()}.
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
     * Neither ceremony: removes every enrolled credential (used when two-factor authentication is
     * disabled).
     */
    public function deleteAllCredentials(User $user): void
    {
        UserWebauthnCredential::deleteAllByUserId($user->getIdOrZero());
    }

    /**
     * Registration: builds the `publicKey` options for a `navigator.credentials.create()` call and
     * stores the ceremony challenge in the session, consumed by {@see self::register()}. `$challenge`
     * is also written out by reference for a caller with no session continuity across the two legs
     * of the ceremony (e.g. a stateless API bridge), to persist itself and pass back in via
     * {@see self::register()}'s `$challengeOverride`.
     *
     * @return stdClass The library's creation options with binary members as base64url strings.
     */
    public function getCreateArgs(User $user, string $domain = '', ?string &$challenge = null): stdClass
    {
        $webauthn = $this->createWebAuthn($domain);

        $createArgs = $webauthn->getCreateArgs(
            $this->userHandle($user),
            $user->getUsername(),
            $user->getProfile()?->getName() ?? $user->getUsername(),
            timeout: 60,
            requireUserVerification: true,
        );

        $challenge = $webauthn->getChallenge()->getBinaryString();
        $this->session->set(self::SESSION_KEY_REGISTER_CHALLENGE, $challenge);

        return $createArgs;
    }

    public function getErrorMessage(): string
    {
        return $this->errorMessage ?? '';
    }

    /**
     * Login: builds the `publicKey` options for a `navigator.credentials.get()` call restricted to
     * the user's enrolled credentials, storing the ceremony challenge for {@see self::verify()}.
     *
     * @return stdClass The library's assertion options with binary members as base64url strings.
     */
    public function getGetArgs(User $user, string $domain = ''): stdClass
    {
        $webauthn = $this->createWebAuthn($domain);
        $credentialIds = [];
        foreach (UserWebauthnCredential::findAllByUserId($user->getIdOrZero()) as $credential) {
            $credentialIds[] = base64_decode($credential->getCredentialId());
        }

        $getArgs = $webauthn->getGetArgs($credentialIds, timeout: 60, requireUserVerification: 'discouraged');

        $this->session->set(self::SESSION_KEY_CONFIRM_CHALLENGE, $webauthn->getChallenge()->getBinaryString());

        return $getArgs;
    }

    /**
     * Registration: verifies the browser's attestation response (from the options built by
     * {@see self::getCreateArgs()}) and persists the new credential. `$challengeOverride` lets a
     * caller with no session continuity (e.g. a stateless API bridge) supply the challenge it stored
     * itself from `getCreateArgs()`'s by-reference output, instead of reading/clearing the session.
     *
     * @param array<array-key, mixed> $data expected keys: `clientDataJSON`, `attestationObject`
     */
    public function register(User $user, array $data, string $domain = '', ?string $challengeOverride = null): bool
    {
        $webauthn = $this->createWebAuthn($domain);
        $challenge = $challengeOverride ?? $this->session->get(self::SESSION_KEY_REGISTER_CHALLENGE);
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
                requireUserVerification: true,
            );
        } catch (WebAuthnException) {
            $this->errorMessage = $this->translateError('voyti-2fa-webauthn.error.verification_failed');
            return false;
        }

        if ($challengeOverride === null) {
            $this->session->remove(self::SESSION_KEY_REGISTER_CHALLENGE);
        }

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
     * Login: verifies the browser's assertion response (from the options built by
     * {@see self::getGetArgs()}) against the user's stored credential and updates its sign counter.
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
                prevSignatureCnt: $credential->getSignCount(),
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
