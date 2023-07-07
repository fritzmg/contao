<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\DataCollector;

use Contao\CoreBundle\ContaoCoreBundle;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\CoreBundle\Framework\FrameworkAwareInterface;
use Contao\CoreBundle\Framework\FrameworkAwareTrait;
use Contao\CoreBundle\Security\Authentication\Token\TokenChecker;
use Contao\LayoutModel;
use Contao\Model\Registry;
use Contao\PageModel;
use Contao\StringUtil;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Node\Expression\Test\NullTest;

/**
 * @internal
 */
class ContaoPageDataCollector extends DataCollector
{
    public function __construct(private RequestStack $requestStack, private UrlGeneratorInterface $urlGenerator, private ContaoFramework $framework)
    {
    }

    public function collect(Request $request, Response $response, \Throwable $exception = null): void
    {
        $page = $this->getPage($request);

        if (null === $page) {
            return;
        }

        $layout = $this->getLayout($request);
        
        $this->data['summary'] = [
            'id' => $page->id,
            'name' => $page->title,
            'title' => $page->pageTitle,
            'layout' => $this->getLayoutName($request),
            'layoutId' => $layout ? $layout->id : '',
            'editPage' => $this->urlGenerator->generate('contao_backend', ['do' => 'page', 'act' => 'edit', 'id' => $page->id, 'ref' => $request->attributes->get('_contao_referer_id')]),
            'editContent' => $this->urlGenerator->generate('contao_backend', ['do' => 'article', 'pn' => $page->id, 'ref' => $request->attributes->get('_contao_referer_id')]),
            'editLayout' => $layout ? $this->urlGenerator->generate('contao_backend', ['do' => 'themes', 'table' => 'tl_layout', 'act' => 'edit', 'id' => $layout->id, 'ref' => $request->attributes->get('_contao_referer_id')]) : '', 
        ];
    }

    /**
     * @return array<string,string|bool>
     */
    public function getSummary(): array
    {
        return $this->getData('summary');
    }

    /**
     * @return array<string,string|bool>
     */
    private function getData(string $key): array
    {
        if (!isset($this->data[$key]) || !\is_array($this->data[$key])) {
            return [];
        }

        return $this->data[$key];
    }

    public function getName(): string
    {
        return 'contao-page';
    }

    public function reset(): void
    {
        $this->data = [];
    }

    private function getLayoutName(Request $request): string
    {
        $layout = $this->getLayout($request);

        if (null === $layout) {
            return '';
        }

        return sprintf('%s (ID %s)', StringUtil::decodeEntities($layout->name), $layout->id);
    }

    private function getPage(Request $request): PageModel|null
    {
        if (($page = $request->attributes->get('pageModel')) instanceof PageModel) {
            return $page;
        }

        if (is_numeric($page)) {
            return PageModel::findWithDetails($page);
        }

        return $GLOBALS['objPage'] ?? null;
    }

    private function getLayout(Request $request): LayoutModel|null
    {
        $objPage = $this->getPage($request);

        if (null === $objPage || !$objPage->layoutId) {
            return null;
        }

        return $this->framework->getAdapter(LayoutModel::class)->findByPk($objPage->layoutId);
    }
}
