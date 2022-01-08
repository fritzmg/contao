<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Menu;

use Contao\CoreBundle\Event\FrontendMenuEvent;
use Contao\CoreBundle\Framework\Adapter;
use Contao\CoreBundle\Monolog\ContaoContext;
use Contao\CoreBundle\Routing\Page\PageRegistry;
use Contao\CoreBundle\Security\Authentication\Token\TokenChecker;
use Contao\CoreBundle\Security\ContaoCorePermissions;
use Contao\Database;
use Contao\Date;
use Contao\PageModel;
use Contao\StringUtil;
use Doctrine\DBAL\Connection;
use Knp\Menu\FactoryInterface;
use Knp\Menu\ItemInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Exception\ExceptionInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

class FrontendMenuBuilder
{
    private FactoryInterface $factory;
    private RequestStack $requestStack;
    private EventDispatcherInterface $dispatcher;
    private Connection $connection;
    private PageRegistry $pageRegistry;
    /**
     * @var Adapter<PageModel>
     */
    private Adapter $pageModelAdapter;
    private TokenChecker $tokenChecker;
    private Security $security;
    private LoggerInterface $logger;
    private Database $database;

    /**
     * @param Adapter<PageModel> $pageModelAdapter
     */
    public function __construct(FactoryInterface $factory, RequestStack $requestStack, EventDispatcherInterface $dispatcher, Connection $connection, PageRegistry $pageRegistry, Adapter $pageModelAdapter, TokenChecker $tokenChecker, Security $security, LoggerInterface $logger, Database $database)
    {
        $this->factory = $factory;
        $this->requestStack = $requestStack;
        $this->dispatcher = $dispatcher;
        $this->connection = $connection;
        $this->pageRegistry = $pageRegistry;
        $this->pageModelAdapter = $pageModelAdapter;
        $this->tokenChecker = $tokenChecker;
        $this->security = $security;
        $this->logger = $logger;
        $this->database = $database;
    }

    public function getMenu(int $pid, array $options = []): ?ItemInterface
    {
        $options = array_replace([
            'showHidden' => false,
            'showProtected' => false,
            'showLevel' => 0,
            'hardLimit' => false,
            'isSitemap' => false,
        ], $options);

        $item = null;

        if (0 !== $pid && null !== ($currentPage = $this->pageModelAdapter->findWithDetails($pid))) {
            /** @var PageModel $currentPage */
            $item = $this->getItem($currentPage, $options);
        }

        // Create a root item if no page is the root (custom nav)
        if (null === $item && 0 === $pid) {
            $item = $this->factory->createItem('root');
        }

        if (null === $item) {
            return null;
        }

        // Get the children
        $pages = $this->getPages($pid, $options);

        /** @var PageModel $page */
        foreach ($pages as ['page' => $page, 'hasSubpages' => $hasSubpages]) {
            $child = $this->getMenu((int) $page->id, $options);

            if (null !== $child) {
                $item->addChild($child);
            }
        }

        $level = $item->getLevel() + 1;
        $activePage = $this->getActivePage();

        $displayChildren = !$options['showLevel']
                || $options['showLevel'] > $level
                || (!$options['hardLimit'] && $activePage && ($activePage->id === $page->id || \in_array($activePage->id, $this->database->getChildRecords($page->id, 'tl_page'), false)));

        $item->setDisplayChildren($displayChildren);

        $this->populateMenuItem($item, $currentPage, $options);

        $menuEvent = new FrontendMenuEvent($this->factory, $item, $pid, $options);
        $this->dispatcher->dispatch($menuEvent);

        return $item;
    }

    private function getItem(PageModel $page, array $options): ?ItemInterface
    {
        // Skip hidden sitemap pages
        if ($options['isSitemap'] && 'map_never' === $page->sitemap) {
            return null;
        }

        if ($page->tabindex > 0) {
            trigger_deprecation('contao/core-bundle', '4.12', 'Using a tabindex value greater than 0 has been deprecated and will no longer work in Contao 5.0.');
        }

        $isMember = $this->security->isGranted('ROLE_MEMBER');

        // Hide the page if it is not protected and only visible to guests (backwards compatibility)
        if ($page->guests && !$page->protected && $isMember) {
            trigger_deprecation('contao/core-bundle', '4.12', 'Using the "show to guests only" feature has been deprecated an will no longer work in Contao 5.0. Use the "protect page" function instead.');
            return null;
        }

        // PageModel->groups is an array after calling loadDetails()
        if (
            $page->protected && !$options['showProtected']
            && (!$options['isSitemap'] || 'map_always' !== $page->sitemap)
            && !$this->security->isGranted(ContaoCorePermissions::MEMBER_IN_GROUPS, $page->groups)
        ) {
            return null;
        }

        $item = $this->factory->createItem($page->title);
        $href = $this->generateUri($page, $item);

        if (null === $href) {
            return null;
        }

        $item->setUri($href);

        return $item;
    }

    private function getActivePage(): ?PageModel
    {
        $request = $this->requestStack->getMainRequest();

        if (null === $request || !$request->attributes->has('pageModel')) {
            if (isset($GLOBALS['objPage']) && $GLOBALS['objPage'] instanceof PageModel) {
                return $GLOBALS['objPage'];
            }

            return null;
        }

        $pageModel = $request->attributes->get('pageModel');

        if ($pageModel instanceof PageModel) {
            return $pageModel;
        }

        if (
            isset($GLOBALS['objPage'])
            && $GLOBALS['objPage'] instanceof PageModel
            && (int) $GLOBALS['objPage']->id === (int) $pageModel
        ) {
            return $GLOBALS['objPage'];
        }

        return $this->pageModelAdapter->findByPk((int) $pageModel);
    }

    private function getPages(int $pid, array $options): array
    {
        // Custom page choice like, e.g., for the custom navigation module
        if (0 === $pid && $options['pages']) {
            return $this->findPagesByIds($options['pages']);
        }

        return $this->findPagesByPid($pid, (bool) $options['showHidden']);
    }

    /**
     * @return array<array{page:PageModel,hasSubpages:bool}>
     */
    private function findPagesByIds(array $pageIds): array
    {
        // Get all active pages and also include root pages if the language is added to the URL (see #72)
        $pages = $this->pageModelAdapter->findPublishedRegularByIds($pageIds, ['includeRoot' => true]);

        if (null === $pages) {
            return [];
        }

        return array_map(
            static fn (PageModel $page): array => [
                'page' => $page,
                'hasSubpages' => false,
            ],
            $pages instanceof \Traversable ? iterator_to_array($pages) : $pages
        );
    }

    /**
     * @return array<array{page:PageModel,hasSubpages:bool}>
     */
    private function findPagesByPid(int $pid, bool $showHidden = false, bool $isSitemap = false): array
    {
        $time = Date::floorToMinute();
        $blnBeUserLoggedIn = $this->tokenChecker->hasBackendUser() && $this->tokenChecker->isPreviewMode();
        $unroutableTypes = $this->pageRegistry->getUnroutableTypes();

        $pages = $this->connection
            ->executeQuery("SELECT p1.id, EXISTS(SELECT * FROM tl_page p2 WHERE p2.pid=p1.id AND p2.type!='root' AND p2.type NOT IN ('".implode("', '", $unroutableTypes)."')".(!$showHidden ? ($isSitemap ? " AND (p2.hide='' OR sitemap='map_always')" : " AND p2.hide=''") : '').(!$blnBeUserLoggedIn ? " AND p2.published='1' AND (p2.start='' OR p2.start<='$time') AND (p2.stop='' OR p2.stop>'$time')" : '').") AS hasSubpages FROM tl_page p1 WHERE p1.pid=:pid AND p1.type!='root' AND p1.type NOT IN ('".implode("', '", $unroutableTypes)."')".(!$showHidden ? ($isSitemap ? " AND (p1.hide='' OR sitemap='map_always')" : " AND p1.hide=''") : '').(!$blnBeUserLoggedIn ? " AND p1.published='1' AND (p1.start='' OR p1.start<='$time') AND (p1.stop='' OR p1.stop>'$time')" : '').' ORDER BY p1.sorting', ['pid' => $pid])
            ->fetchAllAssociative()
        ;

        if (\count($pages) < 1) {
            return [];
        }

        // Load models into the registry with a single query
        $this->pageModelAdapter->findMultipleByIds(array_map(static fn ($row) => $row['id'], $pages));

        return array_map(fn (array $row): array => [
            'page' => $this->pageModelAdapter->findByPk($row['id']),
            'hasSubpages' => (bool) $row['hasSubpages'],
        ], $pages);
    }

    private function generateUri(PageModel $pageModel, ItemInterface $menuItem): ?string
    {
        if ('redirect' === $pageModel->type) {
            $href = $pageModel->url;

            if (0 === strncasecmp($href, 'mailto:', 7)) {
                return StringUtil::encodeEmail($href);
            }

            return $href;
        }

        if ('root' === $pageModel->type) {
            // Overwrite the alias to link to the empty URL or language URL (see #1641)
            $pageModel->alias = 'index';

            return $pageModel->getFrontendUrl();
        }

        if ('forward' === $pageModel->type) {
            if ($pageModel->jumpTo) {
                $jumpTo = $this->pageModelAdapter->findPublishedById($pageModel->jumpTo);
            } else {
                $jumpTo = $this->pageModelAdapter->findFirstPublishedRegularByPid($pageModel->id);
            }

            // Hide the link if the target page is invisible
            if (
                !$jumpTo instanceof PageModel
                || (!$jumpTo->loadDetails()->isPublic && !$this->tokenChecker->isPreviewMode())
            ) {
                $menuItem->setDisplay(false);
            }

            try {
                return $jumpTo->getFrontendUrl();
            } catch (ExceptionInterface $exception) {
                $this->logger->log(LogLevel::ERROR, sprintf('Unable to generate URL for page ID %s: %s', $pageModel->id, $exception->getMessage()), ['contao' => new ContaoContext(__METHOD__, ContaoContext::ERROR)]);

                return null;
            }
        }

        try {
            return $pageModel->getFrontendUrl();
        } catch (ExceptionInterface $exception) {
            $this->logger->log(LogLevel::ERROR, sprintf('Unable to generate URL for page ID %s: %s', $pageModel->id, $exception->getMessage()), ['contao' => new ContaoContext(__METHOD__, ContaoContext::ERROR)]);

            return null;
        }
    }

    private function populateMenuItem(ItemInterface $item, PageModel $page, array $options = []): void
    {
        $request = $this->requestStack->getCurrentRequest();
        $activePage = $this->getActivePage();

        $extra = $page->row();
        $isTrail = $activePage && \in_array($page->id, $activePage->trail, false);

        // Use the path without query string to check for active pages (see #480)
        $path = ltrim($request->getPathInfo(), '/');

        $isActive = $activePage
            && $item->getUri() === $path
            && !($options['isSitemap'] ?? false)
            && (($activePage->id === $page->id) || ('forward' === $page->type && $activePage->id === $page->jumpTo));

        $item->setCurrent($isActive);

        $extra['isActive'] = $isActive;
        $extra['isTrail'] = $isActive ? false : $isTrail;
        $extra['class'] = $this->getCssClass($page, $activePage, $isActive, $isTrail, $item->hasChildren() && $item->getDisplayChildren());
        $extra['title'] = StringUtil::specialchars($page->title, true);
        $extra['pageTitle'] = StringUtil::specialchars($page->pageTitle, true);
        $extra['description'] = str_replace(["\n", "\r"], [' ', ''], (string) $page->description);

        $rel = [];

        if (0 === strncmp($page->robots, 'noindex,nofollow', 16)) {
            $rel[] = 'nofollow';
        }

        // Override the link target
        if ('redirect' === $page->type && $page->target) {
            $rel[] = 'noreferrer';
            $rel[] = 'noopener';

            $item->setLinkAttribute('target', '_blank');
        }

        // Set the rel attribute
        if (!empty($rel)) {
            $item->setLinkAttribute('rel', implode(' ', $rel));
        }

        if ($title = $page->pageTitle ?: $page->title) {
            $item->setLinkAttribute('title', $title);
        }

        if ($page->accesskey) {
            $item->setLinkAttribute('accesskey', $page->accesskey);
        }

        if ($page->tabindex) {
            $item->setLinkAttribute('tabindex', $page->tabindex);
        }

        foreach ($extra as $k => $v) {
            $item->setExtra($k, $v);
        }

        $item->setExtra('pageModel', $page);
    }

    private function getCssClass(PageModel $page, ?PageModel $activePage, bool $isActive, bool $isTrail, bool $hasSubmenu): string
    {
        $classes = [];

        $isForward = $activePage && 'forward' === $page->type && $activePage->id === $page->jumpTo;

        if ($hasSubmenu) {
            $classes[] = 'submenu';
        }

        if ($page->protected) {
            $classes[] = 'protected';
        }

        if ($page->cssClass) {
            $classes[] = $page->cssClass;
        }

        // Mark pages on the same level (see #2419)
        if ($activePage && !$isActive && $page->pid === $activePage->pid) {
            $classes[] = 'sibling';
        }

        if (($isActive && $isForward && $isTrail) || (!$isActive && $isTrail)) {
            $classes[] = 'trail';
        }

        if ($isActive && $isForward) {
            $classes[] = 'forward';
        }

        if ($isActive && !$isForward) {
            $classes[] = 'active';
        }

        return trim(implode(' ', $classes));
    }
}
