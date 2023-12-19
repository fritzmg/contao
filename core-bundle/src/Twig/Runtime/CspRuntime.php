<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Twig\Runtime;

use Contao\CoreBundle\Routing\ResponseContext\Csp\CspHandler;
use Contao\CoreBundle\Routing\ResponseContext\ResponseContextAccessor;
use Nyholm\Psr7\Uri;
use Symfony\Component\HttpFoundation\RequestStack;
use Twig\Extension\RuntimeExtensionInterface;

final class CspRuntime implements RuntimeExtensionInterface
{
    /**
     * @internal
     */
    public function __construct(
        private readonly ResponseContextAccessor $responseContextAccessor,
        private readonly RequestStack $requestStack,
    ) {
    }

    public function getNonce(string $directive): string|null
    {
        $responseContext = $this->responseContextAccessor->getResponseContext();

        if (!$responseContext || !$responseContext->has(CspHandler::class)) {
            return '';
        }

        /** @var CspHandler $csp */
        $csp = $responseContext->get(CspHandler::class);

        return $csp->getNonce($directive);
    }

    public function addSource(string $directive, string $source): void
    {
        $responseContext = $this->responseContextAccessor->getResponseContext();

        if (!$responseContext || !$responseContext->has(CspHandler::class)) {
            return;
        }

        // Automatically add the scheme and host
        if ($request = $this->requestStack->getCurrentRequest()) {
            $uri = new Uri($source);

            if (!$uri->getHost()) {
                $source = (string) $uri
                    ->withScheme($request->getScheme())
                    ->withHost($request->getHost())
                ;
            }
        }

        /** @var CspHandler $csp */
        $csp = $responseContext->get(CspHandler::class);
        $csp->addSource($directive, $source);
    }
}
