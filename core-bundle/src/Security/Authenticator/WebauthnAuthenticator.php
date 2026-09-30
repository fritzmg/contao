<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Security\Authenticator;

use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Contao\CoreBundle\Security\Webauthn\Webauthn;
use Contao\User;
use Scheb\TwoFactorBundle\Security\Http\Authenticator\TwoFactorAuthenticator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * @internal
 */
class WebauthnAuthenticator extends AbstractAuthenticator implements InteractiveAuthenticatorInterface
{
    public function __construct(
        private readonly Webauthn $webauthn,
        private readonly ContaoUserProvider $backendUserProvider,
        private readonly ContaoUserProvider $frontendUserProvider,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->isMethod('POST') && \in_array(
            $request->attributes->get('_route'),
            [
                'contao_backend_webauthn_login_result',
                'contao_frontend_webauthn_login_result',
            ],
            true,
        );
    }

    public function authenticate(Request $request): Passport
    {
        try {
            $credential = $this->webauthn->authenticate($request);
            $scope = $request->attributes->get('_scope');
            $provider = match ($scope) {
                'backend' => $this->backendUserProvider,
                'frontend' => $this->frontendUserProvider,
                default => throw new BadCredentialsException('Unknown passkey scope.'),
            };

            // Load the exact credential owner, even when both scopes share a username.
            return new SelfValidatingPassport(new UserBadge(
                $credential->userHandle,
                static function (string $handle) use ($provider, $scope): User {
                    if (!preg_match('/^'.$scope.'\.([1-9][0-9]*)$/D', $handle, $matches)) {
                        throw new BadCredentialsException('The passkey belongs to another scope.');
                    }

                    $user = $provider->loadUserById((int) $matches[1]);

                    if ($user->getPasskeyUserHandle() !== $handle) {
                        throw new BadCredentialsException('Invalid passkey owner.');
                    }

                    return $user;
                },
            ), [new RememberMeBadge()]);
        } catch (\Throwable $e) {
            throw new BadCredentialsException('Passkey authentication failed.', 0, $e);
        }
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = parent::createToken($passport, $firewallName);

        // Passkeys require user verification and already satisfy the second factor.
        $token->setAttribute(TwoFactorAuthenticator::FLAG_2FA_COMPLETE, true);

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        return new JsonResponse(['status' => 'ok']);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new JsonResponse(['status' => 'error'], Response::HTTP_UNAUTHORIZED);
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
