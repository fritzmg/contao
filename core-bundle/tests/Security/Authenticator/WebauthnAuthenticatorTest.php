<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Security\Authenticator;

use Contao\BackendUser;
use Contao\CoreBundle\Security\Authenticator\WebauthnAuthenticator;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Contao\CoreBundle\Security\Webauthn\Webauthn;
use Contao\CoreBundle\Tests\Fixtures\WebauthnCredentialFixture;
use Contao\FrontendUser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Http\Authenticator\TwoFactorAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;

class WebauthnAuthenticatorTest extends TestCase
{
    #[DataProvider('userHandles')]
    public function testLoadsOnlyTheCredentialOwnerWithinTheConfiguredScope(string $scope, string $handle, bool $valid): void
    {
        $fixture = new WebauthnCredentialFixture($handle);
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willReturn($fixture->credential)
        ;
        $user = $this->createStub('backend' === $scope ? BackendUser::class : FrontendUser::class);
        $user
            ->method('getPasskeyUserHandle')
            ->willReturn($handle)
        ;

        $user
            ->method('getUserIdentifier')
            ->willReturn('admin')
        ;
        $provider = $this->createMock(ContaoUserProvider::class);
        $provider
            ->expects($this->never())
            ->method('loadUserByIdentifier')
        ;

        $provider
            ->expects($valid ? $this->once() : $this->never())
            ->method('loadUserById')
            ->with(1)
            ->willReturn($user)
        ;

        $authenticator = new WebauthnAuthenticator($webauthn, $provider, $scope, 'contao_'.$scope.'_webauthn_login_result');

        if (!$valid) {
            $this->expectException(BadCredentialsException::class);
        }

        $passport = $authenticator->authenticate(new Request());

        $this->assertSame($user, $passport->getUser());
        $this->assertTrue($passport->hasBadge(RememberMeBadge::class));
        $this->assertTrue($authenticator->createToken($passport, 'contao_'.$scope)->getAttribute(TwoFactorAuthenticator::FLAG_2FA_COMPLETE));
    }

    public static function userHandles(): iterable
    {
        yield 'backend' => ['backend', 'backend.1', true];
        yield 'frontend' => ['frontend', 'frontend.1', true];
        yield 'frontend passkey in backend' => ['backend', 'frontend.1', false];
        yield 'backend passkey in frontend' => ['frontend', 'backend.1', false];
        yield 'unknown scope' => ['backend', 'api.1', false];
        yield 'username' => ['backend', 'admin', false];
        yield 'missing scope' => ['backend', '1', false];
        yield 'invalid ID' => ['backend', 'backend.1suffix', false];
        yield 'nonpositive ID' => ['backend', 'backend.0', false];
        yield 'leading zero' => ['frontend', 'frontend.01', false];
        yield 'trailing newline' => ['frontend', "frontend.1\n", false];
    }

    #[DataProvider('scopes')]
    public function testSupportsOnlyPostRequestsToTheConfiguredLoginResultRoute(string $scope): void
    {
        $route = 'contao_'.$scope.'_webauthn_login_result';
        $authenticator = new WebauthnAuthenticator($this->createStub(Webauthn::class), $this->createStub(ContaoUserProvider::class), $scope, $route);
        $request = new Request(attributes: ['_route' => $route]);

        $this->assertFalse($authenticator->supports($request));
        $request->setMethod('POST');
        $this->assertTrue($authenticator->supports($request));
        $otherScope = 'backend' === $scope ? 'frontend' : 'backend';
        $request->attributes->set('_route', 'contao_'.$otherScope.'_webauthn_login_result');
        $this->assertFalse($authenticator->supports($request));
        $request->attributes->set('_route', 'contao_'.$scope.'_webauthn_registration_result');
        $this->assertFalse($authenticator->supports($request));
    }

    public static function scopes(): iterable
    {
        yield 'backend' => ['backend'];
        yield 'frontend' => ['frontend'];
    }

    #[DataProvider('invalidOwners')]
    public function testRejectsAUserWhosePasskeyHandleDoesNotMatch(string $scope, string $userHandle): void
    {
        $fixture = new WebauthnCredentialFixture($scope.'.1');
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willReturn($fixture->credential)
        ;
        $user = $this->createStub('backend' === $scope ? BackendUser::class : FrontendUser::class);
        $user
            ->method('getPasskeyUserHandle')
            ->willReturn($userHandle)
        ;
        $provider = $this->createMock(ContaoUserProvider::class);
        $provider
            ->expects($this->once())
            ->method('loadUserById')
            ->with(1)
            ->willReturn($user)
        ;
        $authenticator = new WebauthnAuthenticator($webauthn, $provider, $scope, 'contao_'.$scope.'_webauthn_login_result');
        $passport = $authenticator->authenticate(new Request());

        $this->expectException(BadCredentialsException::class);
        $passport->getUser();
    }

    public static function invalidOwners(): iterable
    {
        yield 'another backend ID' => ['backend', 'backend.2'];
        yield 'another frontend ID' => ['frontend', 'frontend.2'];
        yield 'another scope in backend' => ['backend', 'frontend.1'];
        yield 'another scope in frontend' => ['frontend', 'backend.1'];
    }

    public function testConvertsValidationFailuresToAuthenticationFailures(): void
    {
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willThrowException(new \RuntimeException('Invalid signature'))
        ;
        $authenticator = new WebauthnAuthenticator($webauthn, $this->createStub(ContaoUserProvider::class), 'backend', 'contao_backend_webauthn_login_result');

        $this->expectException(BadCredentialsException::class);
        $authenticator->authenticate(new Request());
    }

    public function testPropagatesUserLoadingFailures(): void
    {
        $fixture = new WebauthnCredentialFixture();
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willReturn($fixture->credential)
        ;
        $provider = $this->createStub(ContaoUserProvider::class);
        $provider
            ->method('loadUserById')
            ->willThrowException(new UserNotFoundException())
        ;

        $authenticator = new WebauthnAuthenticator($webauthn, $provider, 'backend', 'contao_backend_webauthn_login_result');
        $passport = $authenticator->authenticate(new Request());

        $this->expectException(UserNotFoundException::class);
        $passport->getUser();
    }
}
