<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\NewsBundle\EventListener;

use Contao\ContentModel;
use Contao\Controller;
use Contao\CoreBundle\Cache\EntityCacheTags;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\CoreBundle\Image\ImageFactoryInterface;
use Contao\CoreBundle\InsertTag\InsertTagParser;
use Contao\Environment;
use Contao\File;
use Contao\FilesModel;
use Contao\News;
use Contao\NewsBundle\Event\FetchArticlesForFeedEvent;
use Contao\NewsBundle\Event\TransformArticleForFeedEvent;
use Contao\NewsModel;
use Contao\StringUtil;
use Contao\UserModel;
use FeedIo\Feed\Item;
use FeedIo\Feed\Item\Author;
use FeedIo\Feed\Item\AuthorInterface;
use FeedIo\Feed\Item\Media;
use FeedIo\Feed\ItemInterface;
use Symfony\Component\Filesystem\Path;

class NewsFeedListener
{
    public function __construct(private readonly ContaoFramework $framework, private readonly ImageFactoryInterface $imageFactory, private readonly InsertTagParser $insertTags, private readonly string $projectDir, private readonly EntityCacheTags $cacheTags)
    {
    }

    public function onFetchArticlesForFeed(FetchArticlesForFeedEvent $event): void
    {
        $pageModel = $event->getPageModel();
        $archives = StringUtil::deserialize($pageModel->newsArchives, true);
        $featured = match ($pageModel->feedFeatured) {
            'featured' => true,
            'unfeatured' => false,
            default => null,
        };

        $newsModel = $this->framework->getAdapter(NewsModel::class);

        $articles = $newsModel->findPublishedByPids($archives, $featured, $pageModel->maxFeedItems, 0, [
            'return' => 'Array',
        ]);

        $event->setArticles($articles);
    }

    public function onTransformArticleForFeed(TransformArticleForFeedEvent $event): void
    {
        $article = $event->getArticle();

        $item = new Item();

        $item->setTitle($this->getTitle($article, $item, $event))
            ->setLastModified($this->getLastModified($article, $item, $event))
            ->setLink($this->getLink($article, $item, $event))
            ->setPublicId($this->getPublicId($article, $item, $event))
            ->setContent($this->getContent($article, $item, $event))
        ;

        $author = $this->getAuthor($article, $item, $event);

        if ($author) {
            $item->setAuthor($author);
        }

        $enclosures = $this->getEnclosures($article, $item, $event);

        foreach ($enclosures as $enclosure) {
            $item->addMedia($enclosure);
        }

        $event->setItem($item);
    }

    protected function getTitle(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): string
    {
        return $article->headline;
    }

    protected function getLink(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): string
    {
        return $this->framework->getAdapter(News::class)->generateNewsUrl($article, false, true);
    }

    protected function getPublicId(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): string
    {
        return $item->getLink();
    }

    protected function getLastModified(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): \DateTime
    {
        return (new \DateTime())->setTimestamp($article->date);
    }

    protected function getContent(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): string
    {
        $pageModel = $event->getPageModel();
        $request = $event->getRequest();

        $environment = $this->framework->getAdapter(Environment::class);
        $controller = $this->framework->getAdapter(Controller::class);
        $contentModel = $this->framework->getAdapter(ContentModel::class);

        $description = $article->teaser ?? '';

        // Prepare the description
        if ('source_text' === $pageModel->feedSource) {
            $elements = $contentModel->findPublishedByPidAndTable($article->id, 'tl_news');

            if (null !== $elements) {
                $description = '';
                // Overwrite the request (see #7756)
                $environment->set('request', $item->getLink());

                foreach ($elements as $element) {
                    $description .= $controller->getContentElement($element);
                    $this->cacheTags->tagWithModelInstance($element);
                }

                $environment->set('request', $request->getUri());
            }
        }

        $description = $this->insertTags->replaceInline($description);

        return $controller->convertRelativeUrls($description, $item->getLink());
    }

    protected function getAuthor(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): ?AuthorInterface
    {
        /** @var UserModel $authorModel */
        if (($authorModel = $article->getRelated('author')) instanceof UserModel) {
            return (new Author())->setName($authorModel->name);
        }

        return null;
    }

    protected function getEnclosures(NewsModel $article, ItemInterface $item, TransformArticleForFeedEvent $event): array
    {
        $enclosures = [];
        $uuids = [];

        if ($article->singleSRC) {
            $uuids[] = $article->singleSRC;
        }

        if ($article->addEnclosure) {
            $uuids = [...$uuids, ...StringUtil::deserialize($article->enclosure, true)];
        }

        if (0 === \count($uuids)) {
            return [];
        }

        $pageModel = $event->getPageModel();
        $size = StringUtil::deserialize($pageModel->imgSize, true);

        $filesAdapter = $this->framework->getAdapter(FilesModel::class);
        $files = $filesAdapter->findMultipleByUuids($uuids);

        if (null === $files) {
            return [];
        }

        $baseUrl = $event->getBaseUrl();

        while ($files->next()) {
            $file = new File($files->path);

            $fileUrl = $baseUrl.'/'.$file->path;
            $fileSize = $file->filesize;

            if ($size && $file->isImage) {
                $image = $this->imageFactory->create(Path::join($this->projectDir, $file->path), $size);
                $fileUrl = $baseUrl.'/'.$image->getUrl($this->projectDir);
                $file = new File(Path::makeRelative($image->getPath(), $this->projectDir));
                $fileSize = $file->exists() ? $file->filesize : null;
            }

            $media = (new Media())
                ->setUrl($fileUrl)
                ->setType($file->mime)
            ;

            if ($fileSize) {
                $media->setLength($fileSize);
            }

            $enclosures[] = $media;
        }

        return $enclosures;
    }
}
