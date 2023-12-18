<?php

namespace Contao\CoreBundle\Routing\ResponseContext\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Symfony\Component\HttpFoundation\Request;

final class ContentSecurityPolicyHandler
{
    private bool $reportOnly = false;
    private string $nonce;
    private array $signatures = [];

    private static $validNonceDirectives = ['script-src', 'style-src', 'script-src-elem', 'style-src-elem'];
    private static $validHashDirectives = ['script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr'];

    public function __construct(private readonly DirectiveSet $directives)
    {
    }

    public function setReportOnly(bool $reportOnly): self
    {
        $this->reportOnly = $reportOnly;

        return $this;
    }

    public function getReportOnly(): bool
    {
        return $this->reportOnly;
    }

    public function setDirectives(DirectiveSet $directives): self
    {
        $this->directives = $directives;

        return $this;
    }

    public function getDirectives(): DirectiveSet
    {
        return $this->directives;
    }

    public function getNonce(string $directive): ?string
    {
        if (!\in_array($directive, self::$validNonceDirectives, true)) {
            throw new \InvalidArgumentException('Invalid directive');
        }

        if (!$this->isDirectiveSet($directive)) {
            return null;
        }

        if (!$this->nonce) {
            $this->nonce = base64_encode(random_bytes(18));
        }

        $this->signatures[$directive][] = 'nonce-'.$this->nonce;

        return $this->nonce;
    }

    public function getHash(string $directive, string $script, string $algorithm = 'sha384'): ?string
    {
        if (!\in_array($directive, self::$validHashDirectives, true)) {
            throw new \InvalidArgumentException('Invalid directive');
        }

        if (!$this->isDirectiveSet($directive)) {
            return null;
        }

        $hash = base64_encode(hash($algorithm, $script, true));

        $this->signatures[$directive][] = $algorithm.'-'.$hash;

        return $hash;
    }

    /** 
     * Sets or appends a source for a directive, e.g. frame-src https://www.youtube.com/…
     * 
     * @param string $directive The directive for which the source should be added.
     * @param string $source The source for the directive.
     * @param bool $autoIgnore Does not add the source if no directive (or its fallback) is set yet.
     */
    public function addSource(string $directive, string $source, bool $autoIgnore = true): self
    {
        if (!$this->isDirectiveSet($directive, true) || !$autoIgnore) {
            $current = $this->directives->getDirective($directive);
            $this->directives->setDirective($directive, trim($current.' '.$source));
        }

        return $this;
    }

    /** 
     * Checks if a directive or any of its fallbacks are set.
     * 
     * @param string $directive The directive.
     * @param bool $includeFallback Whether to include the fallbacks of the directive in the check.
     */
    public function isDirectiveSet(string $directive, bool $includeFallback = true): bool
    {
        if ($this->directives->getDirective($directive)) {
            return true;
        }

        if (!$includeFallback || (DirectiveSet::getNames()[$directive] ?? null) !== DirectiveSet::TYPE_SRC_LIST) {
            return false;
        }

        switch ($directive) {
            case 'script-src-attr':
            case 'script-src-elem': return $this->isDirectiveSet('script-src', $includeFallback);
            case 'style-src-attr':
            case 'style-src-elem': return $this->isDirectiveSet('style-src', $includeFallback);
            default: return $this->isDirectiveSet('default-src', $includeFallback);
        }
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
