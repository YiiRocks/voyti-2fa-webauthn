<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Model;

use YiiRocks\Voyti\Model\User;
use YiiRocks\Voyti\TwoFactor\Webauthn\Model\UserWebauthnCredential;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\DatabaseTestCase;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\UserFactoryTrait;
use YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support\WebauthnCredentialFactoryTrait;

final class UserWebauthnCredentialTest extends DatabaseTestCase
{
    use UserFactoryTrait;
    use WebauthnCredentialFactoryTrait;

    public function testCrudAndFinders(): void
    {
        $user = $this->createUser(username: 'wa_model', email: 'wa_model@example.com');

        $credential = new UserWebauthnCredential();
        $credential->setUserId((int) $user->getId());
        $credential->setCredentialId('base64-credential');
        $credential->setPublicKey('-----BEGIN PUBLIC KEY-----');
        $credential->setSignCount(3);
        $credential->setAaguid('aaguid-hex');
        $credential->setBackupEligible(true);
        $credential->setBackedUp(true);
        $credential->setCreatedAt(1000);
        $credential->setUpdatedAt(2000);
        $credential->save();

        $found = UserWebauthnCredential::findByUserIdAndCredentialId((int) $user->getId(), 'base64-credential');
        self::assertNotNull($found);
        self::assertSame((int) $user->getId(), $found->getUserId());
        self::assertSame('base64-credential', $found->getCredentialId());
        self::assertSame('-----BEGIN PUBLIC KEY-----', $found->getPublicKey());
        self::assertSame(3, $found->getSignCount());
        self::assertSame('aaguid-hex', $found->getAaguid());
        self::assertTrue($found->isBackupEligible());
        self::assertTrue($found->isBackedUp());
        self::assertSame(1000, $found->getCreatedAt());
        self::assertSame(2000, $found->getUpdatedAt());
        self::assertNotNull($found->getId());

        // A second key for the same user, and a different user's key that must stay untouched.
        $this->createCredential($user, 'base64-credential-2');
        $other = $this->createUser(username: 'wa_model_other', email: 'wa_model_other@example.com');
        $this->createCredential($other, 'base64-credential-other');

        // Scenario 2: finders return every enrolled key for the user, filtered by user and id
        self::assertCount(2, UserWebauthnCredential::findAllByUserId((int) $user->getId()));
        self::assertNull(UserWebauthnCredential::findByUserIdAndCredentialId((int) $user->getId(), 'unknown'));
        self::assertNull(UserWebauthnCredential::findByUserIdAndCredentialId(999999, 'base64-credential'));
        self::assertSame([], UserWebauthnCredential::findAllByUserId(999999));

        // Scenario 3: boolean defaults are false
        $fresh = new UserWebauthnCredential();
        self::assertFalse($fresh->isBackupEligible());
        self::assertFalse($fresh->isBackedUp());

        // Scenario 4: deleteAll removes every row for that user only, leaving other users' keys
        UserWebauthnCredential::deleteAllByUserId((int) $user->getId());
        self::assertSame([], UserWebauthnCredential::findAllByUserId((int) $user->getId()));
        self::assertCount(1, UserWebauthnCredential::findAllByUserId((int) $other->getId()));
    }
}
