<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\NewsBundle\Migration;

use Contao\CoreBundle\Migration\AbstractMigration;
use Contao\CoreBundle\Migration\MigrationResult;
use Doctrine\DBAL\Connection;
use Psr\Log\LoggerInterface;

class FeedMigration extends AbstractMigration
{
    public function __construct(private readonly Connection $connection, private readonly LoggerInterface $logger)
    {
    }

    public function shouldRun(): bool
    {
        if (!$this->connection->createSchemaManager()->tablesExist(['tl_news_feed'])) {
            return false;
        }

        $result = $this->connection->executeQuery('SELECT COUNT(id) AS count FROM tl_news_feed')->fetchFirstColumn();

        return !empty($result) && $result[0] > 0;
    }

    public function run(): MigrationResult
    {
        // Add new columns to `tl_page`
        $newFields = [
            'newsArchives' => 'blob NULL',
            'feedFormat' => "varchar(32) NOT NULL default 'rss'",
            'feedSource' => "varchar(32) NOT NULL default 'source_teaser'",
            'maxFeedItems' => 'smallint(5) unsigned NOT NULL default 25',
            'feedFeatured' => "varchar(16) COLLATE ascii_bin NOT NULL default 'all_items'",
            'imgSize' => "varchar(255) NOT NULL default ''",
        ];

        foreach ($newFields as $field => $definition) {
            $this->connection->executeStatement("
                ALTER TABLE
                    tl_page
                ADD
                    $field $definition
            ");
        }

        // Migrate data from `tl_news_feeds` to `tl_page`
        $feeds = $this->connection->executeQuery('SELECT * FROM tl_news_feed')->fetchAllAssociative();

        foreach ($feeds as $feed) {
            $rootPage = $this->findMatchingRootPage($feed);

            if (!$rootPage) {
                $this->logger->warning('Could not migrate feed '.$feed['title'].' because there is no root page');
                continue;
            }

            $this->connection->insert('tl_page', [
                'type' => 'news_feed',
                'pid' => $rootPage,
                'tstamp' => $feed['tstamp'],
                'title' => $feed['title'],
                'alias' => 'share/'.$feed['alias'],
                'description' => $feed['description'],
                'feedSource' => $feed['source'],
                'feedFormat' => $feed['format'],
                'newsArchives' => $feed['archives'],
                'maxFeedItems' => $feed['maxItems'],
                'imgSize' => $feed['imgSize'],
            ]);
            $this->connection->delete('tl_news_feed', ['id' => $feed['id']]);
        }

        return $this->createResult(true);
    }

    private function findMatchingRootPage(array $feed): ?int
    {
        $feedBase = preg_replace('/^https?:\/\//', '', $feed['feedBase']);

        $page = $this->connection
            ->executeQuery("SELECT id FROM tl_page WHERE type = 'root' AND dns = :dns AND language = :language LIMIT 1", ['dns' => $feedBase, 'language' => $feed['language']])
            ->fetchFirstColumn()
        ;

        // Find first root page, if none matches by dns and language
        if (!$page) {
            $page = $this->connection
                ->executeQuery("SELECT id FROM tl_page WHERE type = 'root' ORDER BY sorting ASC LIMIT 1")
                ->fetchFirstColumn()
            ;
        }

        return $page[0] ?? null;
    }
}
