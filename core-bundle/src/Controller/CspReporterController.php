<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Controller;

use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\PageModel;
use Nelmio\SecurityBundle\Controller\ContentSecurityPolicyController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

#[Route(path: '/_contao/csp/report/{page}', name: self::class, methods: [Request::METHOD_POST])]
final class CspReporterController
{
    public function __construct(
        private readonly ContaoFramework $framework,
        private readonly ContentSecurityPolicyController|null $nelmioController,
    ) {
    }

    public function __invoke(Request $request, int $page): Response
    {
        if (!$this->nelmioController) {
            throw new NotFoundHttpException('CSP report logging only works with the NelmioSecurityBundle enabled.');
        }

        $this->framework->initialize();

        /** @var PageModel $pageModelAdapter */
        $pageModelAdapter = $this->framework->getAdapter(PageModel::class);

        if (!$page || !$pageModelAdapter->findWithDetails($page)?->cspReportLog) {
            throw new NotFoundHttpException('CSP report logging not enabled on this page.');
        }

        // Forward to controller from nelmio/security-bundle
        return $this->nelmioController->indexAction($request);
    }
}
