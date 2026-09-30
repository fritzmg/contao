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

use Contao\CoreBundle\Security\Webauthn\Webauthn;
use Contao\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * @internal
 */
class WebauthnController extends AbstractController
{
    public function __construct(private readonly Webauthn $webauthn)
    {
    }

    #[Route('/_contao/webauthn/backend/login/options', name: 'contao_backend_webauthn_login_options', defaults: ['_scope' => 'backend'], methods: ['POST'])]
    #[Route('/_contao/webauthn/frontend/login/options', name: 'contao_frontend_webauthn_login_options', defaults: ['_scope' => 'frontend'], methods: ['POST'])]
    public function loginOptions(Request $request): JsonResponse
    {
        try {
            return $this->optionsResponse($this->webauthn->createRequestOptions($request));
        } catch (\Throwable) {
            return new JsonResponse(['status' => 'error'], Response::HTTP_BAD_REQUEST);
        }
    }

    #[Route('/_contao/webauthn/backend/login/result', name: 'contao_backend_webauthn_login_result', defaults: ['_scope' => 'backend'], methods: ['POST'])]
    #[Route('/_contao/webauthn/frontend/login/result', name: 'contao_frontend_webauthn_login_result', defaults: ['_scope' => 'frontend'], methods: ['POST'])]
    public function loginResult(): JsonResponse
    {
        // Successful requests are handled by the firewall authenticator.
        return new JsonResponse(['status' => 'error'], Response::HTTP_UNAUTHORIZED);
    }

    #[Route('%contao.backend.route_prefix%/webauthn/add/options', name: 'contao_backend_webauthn_registration_options', defaults: ['_scope' => 'backend'], methods: ['POST'])]
    #[Route('/_contao/webauthn/add/options', name: 'contao_frontend_webauthn_registration_options', defaults: ['_scope' => 'frontend'], methods: ['POST'])]
    public function registrationOptions(Request $request): JsonResponse
    {
        $user = $this->getAuthenticatedUser();

        try {
            return $this->optionsResponse($this->webauthn->createCreationOptions($request, $user));
        } catch (\Throwable) {
            return new JsonResponse(['status' => 'error'], Response::HTTP_BAD_REQUEST);
        }
    }

    #[Route('%contao.backend.route_prefix%/webauthn/add/result', name: 'contao_backend_webauthn_registration_result', defaults: ['_scope' => 'backend'], methods: ['POST'])]
    #[Route('/_contao/webauthn/add/result', name: 'contao_frontend_webauthn_registration_result', defaults: ['_scope' => 'frontend'], methods: ['POST'])]
    public function registrationResult(Request $request): JsonResponse
    {
        $user = $this->getAuthenticatedUser();

        try {
            $this->webauthn->register($request, $user);

            return new JsonResponse(['status' => 'ok']);
        } catch (\Throwable) {
            return new JsonResponse(['status' => 'error'], Response::HTTP_BAD_REQUEST);
        }
    }

    private function getAuthenticatedUser(): User
    {
        $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');
        $user = $this->getUser();

        if (!$user instanceof User) {
            throw $this->createAccessDeniedException();
        }

        return $user;
    }

    private function optionsResponse(string $options): JsonResponse
    {
        return new JsonResponse(['status' => 'ok', ...json_decode($options, true, flags: JSON_THROW_ON_ERROR)]);
    }
}
