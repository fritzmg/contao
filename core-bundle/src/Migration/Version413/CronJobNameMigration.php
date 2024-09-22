<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Migration\Version413;

use Contao\CoreBundle\Migration\AbstractMigration;
use Contao\CoreBundle\Migration\MigrationResult;
use Doctrine\DBAL\Connection;

/**
 * Truncates tl_cron_job once to remove outdated cron job names, using the
 * old name of the "contao.cron.purge_preview_links" cron job as an indicator.
 *
 * @internal
 */
class CronJobNameMigration extends AbstractMigration
{
    private const LEGACY_NAME = 'Contao\CoreBundle\Cron\PurgePreviewLinksCron';
    private Connection $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    public function shouldRun(): bool
    {
        $schemaManager = $this->connection->createSchemaManager();

        if (!$schemaManager->tablesExist(['tl_cron_job'])) {
            return false;
        }

        if (!isset($schemaManager->listTableColumns('tl_cron_job')['name'])) {
            return false;
        }

        return (bool) $this->connection->fetchOne('SELECT TRUE FROM tl_cron_job WHERE name = ? LIMIT 1', [self::LEGACY_NAME]);
    }

    public function run(): MigrationResult
    {
        $this->connection->executeQuery('TRUNCATE tl_cron_job');

        return $this->createResult(true);
    }
}
