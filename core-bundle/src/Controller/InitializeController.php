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

use Contao\CoreBundle\Response\InitializeControllerResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\HttpKernel\TerminableInterface;
use Symfony\Component\Routing\Annotation\Route;

/**
 * Custom controller to support legacy entry points.
 *
 * @deprecated Deprecated in Contao 4.0, to be removed in Contao 5.0
 */
class InitializeController extends AbstractController
{
    /**
     * Initializes the Contao framework.
     *
     * @throws \RuntimeException
     *
     * @Route("/_contao/initialize", name="contao_initialize")
     */
    public function indexAction(): InitializeControllerResponse
    {
        @trigger_error('Custom entry points are deprecated and will no longer work in Contao 5.0.', E_USER_DEPRECATED);

        $masterRequest = $this->get('request_stack')->getMasterRequest();

        if (null === $masterRequest) {
            throw new \RuntimeException('The request stack did not contain a master request.');
        }

        $realRequest = Request::createFromGlobals();

        // Necessary to generate the correct base path
        foreach (['REQUEST_URI', 'SCRIPT_NAME', 'SCRIPT_FILENAME', 'PHP_SELF'] as $name) {
            $realRequest->server->set(
                $name,
                str_replace(TL_SCRIPT, 'app.php', $realRequest->server->get($name))
            );
        }

        $realRequest->attributes->replace($masterRequest->attributes->all());

        // Empty the request stack to make our real request the master
        do {
            $pop = $this->get('request_stack')->pop();
        } while ($pop);

        // Initialize the framework with the real request
        $this->get('request_stack')->push($realRequest);
        $this->get('contao.framework')->initialize();

        // Add the master request again. When Kernel::handle() is finished,
        // it will pop the current request, resulting in the real request being active.
        $this->get('request_stack')->push($masterRequest);

        set_exception_handler(function ($e) use ($realRequest): void {
            // Do not catch PHP7 Throwables
            if (!$e instanceof \Exception) {
                throw $e;
            }

            $this->handleException($e, $realRequest, HttpKernelInterface::MASTER_REQUEST);
        });

        return new InitializeControllerResponse('', 204);
    }

    /**
     * Handles an exception by trying to convert it to a Response object.
     *
     * @param int $type HttpKernelInterface::MASTER_REQUEST or HttpKernelInterface::SUB_REQUEST
     *
     * @see HttpKernel::handleException()
     */
    private function handleException(\Exception $e, Request $request, $type): void
    {
        $event = new GetResponseForExceptionEvent($this->get('http_kernel'), $request, $type, $e);
        $this->get('event_dispatcher')->dispatch(KernelEvents::EXCEPTION, $event);

        // A listener might have replaced the exception
        $e = $event->getException();

        if (!$response = $event->getResponse()) {
            throw $e;
        }

        // The developer asked for a specific status code
        if (
            !$event->isAllowingCustomResponseCode()
            && !$response->isClientError()
            && !$response->isServerError()
            && !$response->isRedirect()
        ) {
            // Ensure that we actually have an error response
            if ($e instanceof HttpExceptionInterface) {
                // Keep the HTTP status code and headers
                $response->setStatusCode($e->getStatusCode());
                $response->headers->add($e->getHeaders());
            } else {
                $response->setStatusCode(500);
            }
        }

        $response->send();

        /** @var KernelInterface&TerminableInterface $kernel */
        $kernel = $this->get('kernel');
        $kernel->terminate($request, $response);

        exit;
    }
}
