<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Routing;

use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\PageModel;
use Symfony\Component\HttpFoundation\RequestStack;

class PageModelLocator
{
    private RequestStack $requestStack;
    private ContaoFramework $framework;

    public function __construct(RequestStack $requestStack, ContaoFramework $framework)
    {
        $this->requestStack = $requestStack;
        $this->framework = $framework;
    }

    public function getCurrentPageModel(): ?PageModel
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

        $this->framework->initialize();

        return $this->framework->getAdapter(PageModel::class)->findByPk((int) $pageModel);
    }
}
