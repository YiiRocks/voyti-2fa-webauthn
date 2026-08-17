<?php

declare(strict_types=1);

use Yiisoft\Db\Migration\MigrationBuilder;
use Yiisoft\Db\Migration\RevertibleMigrationInterface;
use Yiisoft\Db\Migration\TransactionalMigrationInterface;
use Yiisoft\Db\Schema\Column\ColumnBuilder;

final class M260811000000_create_user_webauthn_credential_table implements RevertibleMigrationInterface, TransactionalMigrationInterface
{
    public function down(MigrationBuilder $b): void
    {
        $b->dropTable('{{%user_webauthn_credential}}');
    }

    public function up(MigrationBuilder $b): void
    {
        $b->createTable('{{%user_webauthn_credential}}', [
            'id' => ColumnBuilder::primaryKey(),
            'user_id' => ColumnBuilder::integer()->notNull(),
            // Credential ids are conventionally <= 1023 bytes, but the attested-credential-data wire
            // format encodes their length in 2 bytes, so an authenticator may legitimately return up
            // to 65535 bytes. TEXT holds the base64 of any of these without picking a magic length.
            'credential_id' => ColumnBuilder::text()->notNull(),
            'public_key' => ColumnBuilder::text()->notNull(),
            'sign_count' => ColumnBuilder::integer()->notNull()->defaultValue(0),
            'aaguid' => ColumnBuilder::string(64),
            'backup_eligible' => ColumnBuilder::boolean()->notNull()->defaultValue(false),
            'backed_up' => ColumnBuilder::boolean()->notNull()->defaultValue(false),
            'created_at' => ColumnBuilder::integer()->notNull(),
            'updated_at' => ColumnBuilder::integer()->notNull(),
            'FOREIGN KEY ([[user_id]]) REFERENCES {{%user}} ([[id]]) ON DELETE CASCADE ON UPDATE RESTRICT',
        ]);

        // A full-length unique index on credential_id would exceed InnoDB's 3072-byte key limit
        // under utf8mb4. Credential ids are opaque and effectively random, so a prefix-length unique
        // index is collision-free in practice while staying within the limit.
        $b->execute(
            'CREATE UNIQUE INDEX [[idx-user_webauthn_credential-credential_id]] '
            . 'ON {{%user_webauthn_credential}} ([[credential_id]](767))',
        );
    }
}
