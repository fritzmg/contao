<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CommentsBundle\Tests\EventListener;

use Contao\CommentsBundle\Cron\PurgeSubscriptionsCronJob;
use Contao\CommentsNotifyModel;
use Contao\Model\Collection;
use Contao\TestCase\ContaoTestCase;

class PurgeSubscriptionsCronJobTest extends ContaoTestCase
{
    public function testDeletesExpiredSubscriptions(): void
    {
        $commentsNotifyModel = $this->createMock(CommentsNotifyModel::class);
        $commentsNotifyModel
            ->expects($this->exactly(1))
            ->method('delete')
        ;

        $commentsNotifyModelAdapter = $this->mockAdapter(['findExpiredSubscriptions']);
        $commentsNotifyModelAdapter
            ->expects($this->exactly(1))
            ->method('findExpiredSubscriptions')
            ->willReturn(new Collection([$commentsNotifyModel], CommentsNotifyModel::getTable()))
        ;

        $framework = $this->mockContaoFramework([CommentsNotifyModel::class => $commentsNotifyModelAdapter]);

        (new PurgeSubscriptionsCronJob($framework, null))();
    }
}
