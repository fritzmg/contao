<?php

namespace Contao\CoreBundle\Routing\ResponseContext\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Symfony\Component\HttpFoundation\Request;

final class ContentSecurityPolicyHandler
{
    private DirectiveSet $directives;
    private bool $reportOnly = false;
    private string $nonce;
    private string $scriptNonce;
    private string $styleNonce;
    private array $signatures = [];

    public function __construct(
        private readonly PolicyManager $policyManager,
        private readonly NonceGenerator $nonceGenerator,
    ) {
        $this->directives = new DirectiveSet($this->policyManager);
    }

    public function parseContentSecurityPolicyHeader(string $header): self
    {
        // TODO

        return $this;
    }

    public function getReportOnly(): bool
    {
        return $this->reportOnly;
    }

    public function setReportOnly(bool $reportOnly): self
    {
        $this->reportOnly = $reportOnly;

        return $this;
    }

    public function getDirectives(): DirectiveSet
    {
        return $this->directives;
    }

    public function getNonce(string $directive): ?string
    {
        if (!\in_array($directive, ['script-src', 'style-src', 'script-src-elem', 'style-src-elem'], true)) {
            throw new \InvalidArgumentException('Invalid directive');
        }

        if (!$this->directives->getDirective($directive)) {
            return null;
        }

        if (!$this->nonce) {
            $this->nonce = $this->nonceGenerator->generate();
        }

        $this->signatures[$directive][] = $this->nonce;

        return $this->nonce;
    }

    public function getHash(string $directive, string $code): ?string
    {
        if (!\in_array($directive, ['script-src', 'script-src-elem', 'script-src-attr'], true)) {
            throw new \InvalidArgumentException('Invalid directive');
        }
    }

    /** 
     * Adds a source for a directive, e.g. frame-src https://www.youtube.com/…
     * 
     * @param $directive The directive for which the source should be added.
     * @param $source The source for the directive.
     * @param $autoIgnore Does not add the source if no directive is set yet.
     */
    public function addSource(string $directive, string $source, bool $autoIgnore = true): self
    {
        $current = $this->directives->getDirective($directive);

        if ($current || !$autoIgnore) {
            $this->directives->setDirective($directive, trim($current.' '.$source));
        }

        return $this;
    }

    public function buildHeaders(Request $request, bool $reportOnly, bool $compatHeaders): array
    {
        $headerValue = $this->directives->buildHeaderValue($request, $this->signatures);

        if (!$headerValue) {
            return [];
        }

        $hn = function ($name) use ($reportOnly) {
            return $name.($reportOnly ? '-Report-Only' : '');
        };

        $headers = array(
            $hn('Content-Security-Policy') => $headerValue,
        );

        if ($compatHeaders) {
            $headers[$hn('X-Content-Security-Policy')] = $headerValue;
        }

        return $headers;
    }
}
