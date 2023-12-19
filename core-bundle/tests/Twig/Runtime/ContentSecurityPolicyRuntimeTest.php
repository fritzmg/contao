<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Twig\Runtime;

use Contao\CoreBundle\Routing\ResponseContext\ContentSecurityPolicy\ContentSecurityPolicyHandler;
use Contao\CoreBundle\Routing\ResponseContext\ResponseContext;
use Contao\CoreBundle\Routing\ResponseContext\ResponseContextAccessor;
use Contao\CoreBundle\Tests\TestCase;
use Contao\CoreBundle\Twig\Runtime\ContentSecurityPolicyRuntime;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Symfony\Component\HttpFoundation\RequestStack;

class ContentSecurityPolicyRuntimeTest extends TestCase
{
    public function testRetrievesNonceFromCspBuilder(): void
    {
        $directives = new DirectiveSet(new PolicyManager());
        $directives->setDirective('script-src', "'self'");

        $cspHandler = new ContentSecurityPolicyHandler($directives);

        $responseContext = (new ResponseContext())->add($cspHandler);

        $responseContextAccessor = $this->createMock(ResponseContextAccessor::class);
        $responseContextAccessor
            ->expects($this->once())
            ->method('getResponseContext')
            ->willReturn($responseContext)
        ;

        $runtime = new ContentSecurityPolicyRuntime($responseContextAccessor, new RequestStack());

        $this->assertNotNull($runtime->getNonce('script-src'));
    }

    public function testAddsCspSource(): void
    {
        $directives = new DirectiveSet(new PolicyManager());
        $directives->setDirective('script-src', "'self'");

        $cspHandler = new ContentSecurityPolicyHandler($directives);

        $responseContext = (new ResponseContext())->add($cspHandler);

        $responseContextAccessor = $this->createMock(ResponseContextAccessor::class);
        $responseContextAccessor
            ->expects($this->once())
            ->method('getResponseContext')
            ->willReturn($responseContext)
        ;

        $runtime = new ContentSecurityPolicyRuntime($responseContextAccessor, new RequestStack());

        $runtime->addSource('script-src', 'https://example.com/files/foo/foobar.js');

        $this->assertSame("'self' https://example.com/files/foo/foobar.js", $directives->getDirective('script-src'));
    }
}
