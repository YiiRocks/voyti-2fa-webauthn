<?php

declare(strict_types=1);

namespace YiiRocks\Voyti\TwoFactor\Webauthn\tests\Support;

use YiiRocks\Voyti\TwoFactor\Webauthn\tests\TestCase;

/**
 * Test case that boots the in-memory SQLite database (module + RBAC migrations) for each test.
 */
abstract class DatabaseTestCase extends TestCase
{
    use DatabaseSetupTrait;

    protected function setUp(): void
    {
        $this->setUpDatabase();
    }

    protected function tearDown(): void
    {
        $this->tearDownDatabase();
    }
}
