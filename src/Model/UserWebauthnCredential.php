<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\Model;

use Yiisoft\ActiveRecord\ActiveRecord;
use Yiisoft\ActiveRecord\Trait\PrivatePropertiesTrait;

/**
 * ActiveRecord for the `user_webauthn_credential` table: one row per WebAuthn authenticator
 * (security key/passkey) a user has enrolled for two-factor authentication. `credential_id` is the
 * base64-encoded binary credential id returned by the authenticator, `public_key` the PEM-encoded
 * COSE public key needed to verify future assertions.
 */
final class UserWebauthnCredential extends ActiveRecord
{
    use PrivatePropertiesTrait;

    private ?string $aaguid = null;
    private int|bool $backed_up = false;
    private int|bool $backup_eligible = false;
    private int $created_at = 0;
    private string $credential_id = '';
    private ?int $id = null;
    private string $public_key = '';
    private int $sign_count = 0;
    private int $updated_at = 0;
    private int $user_id = 0;

    public static function deleteAllByUserId(int $userId): void
    {
        (new self())->deleteAll(['user_id' => $userId]);
    }

    /**
     * @return UserWebauthnCredential[]
     *
     * @psalm-return list<UserWebauthnCredential>
     */
    public static function findAllByUserId(int $userId): array
    {
        /** @var list<UserWebauthnCredential> $credentials */
        $credentials = self::query()->where(['user_id' => $userId])->all();
        return $credentials;
    }

    public static function findByUserIdAndCredentialId(int $userId, string $credentialId): ?UserWebauthnCredential
    {
        /** @var ?UserWebauthnCredential $credential */
        $credential = self::query()->where(['user_id' => $userId, 'credential_id' => $credentialId])->one();
        return $credential;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function getCreatedAt(): int
    {
        return $this->created_at;
    }

    public function getCredentialId(): string
    {
        return $this->credential_id;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getPublicKey(): string
    {
        return $this->public_key;
    }

    public function getSignCount(): int
    {
        return $this->sign_count;
    }

    public function getUpdatedAt(): int
    {
        return $this->updated_at;
    }

    public function getUserId(): int
    {
        return $this->user_id;
    }

    public function isBackedUp(): bool
    {
        return (bool) $this->backed_up;
    }

    public function isBackupEligible(): bool
    {
        return (bool) $this->backup_eligible;
    }

    public function setAaguid(?string $aaguid): void
    {
        $this->aaguid = $aaguid;
    }

    public function setBackedUp(int|bool $backedUp): void
    {
        $this->backed_up = $backedUp;
    }

    public function setBackupEligible(int|bool $backupEligible): void
    {
        $this->backup_eligible = $backupEligible;
    }

    public function setCreatedAt(int $createdAt): void
    {
        $this->created_at = $createdAt;
    }

    public function setCredentialId(string $credentialId): void
    {
        $this->credential_id = $credentialId;
    }

    public function setPublicKey(string $publicKey): void
    {
        $this->public_key = $publicKey;
    }

    public function setSignCount(int $signCount): void
    {
        $this->sign_count = $signCount;
    }

    public function setUpdatedAt(int $updatedAt): void
    {
        $this->updated_at = $updatedAt;
    }

    public function setUserId(int $userId): void
    {
        $this->user_id = $userId;
    }
}
