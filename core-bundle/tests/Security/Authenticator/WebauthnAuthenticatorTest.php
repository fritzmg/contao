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
use Contao\User;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Scheb\TwoFactorBundle\Security\Http\Authenticator\TwoFactorAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;

class WebauthnAuthenticatorTest extends TestCase
{
    #[DataProvider('users')]
    public function testLoadsOnlyTheCredentialOwnerFromTheSelectedProvider(string|null $scope, string $handle, bool $valid): void
    {
        $fixture = new WebauthnCredentialFixture($handle);
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willReturn($fixture->credential)
        ;
        $backend = $this->createMock(ContaoUserProvider::class);
        $frontend = $this->createMock(ContaoUserProvider::class);
        $backend
            ->expects($this->never())
            ->method('loadUserByIdentifier')
        ;

        $frontend
            ->expects($this->never())
            ->method('loadUserByIdentifier')
        ;

        foreach (['backend' => $backend, 'frontend' => $frontend] as $providerScope => $provider) {
            $user = $this->createStub('backend' === $providerScope ? BackendUser::class : FrontendUser::class);
            $user
                ->method('getPasskeyUserHandle')
                ->willReturn($providerScope.'.1')
            ;

            $user
                ->method('getUserIdentifier')
                ->willReturn('admin')
            ;

            $provider
                ->expects($valid && $providerScope === $scope ? $this->once() : $this->never())
                ->method('loadUserById')
                ->with(1)
                ->willReturn($user)
            ;
        }

        $request = new Request(attributes: ['_scope' => $scope]);
        $authenticator = new WebauthnAuthenticator($webauthn, $backend, $frontend);

        if (!$valid) {
            $this->expectException(BadCredentialsException::class);
        }

        $passport = $authenticator->authenticate($request);
        $user = $passport->getUser();
        $this->assertInstanceOf(User::class, $user);
        $this->assertSame($handle, $user->getPasskeyUserHandle());
        $this->assertTrue($passport->hasBadge(RememberMeBadge::class));
        $this->assertTrue($authenticator->createToken($passport, 'contao_'.$scope)->getAttribute(TwoFactorAuthenticator::FLAG_2FA_COMPLETE));
    }

    public static function users(): iterable
    {
        yield 'backend' => ['backend', 'backend.1', true];
        yield 'frontend' => ['frontend', 'frontend.1', true];
        yield 'frontend passkey in backend' => ['backend', 'frontend.1', false];
        yield 'backend passkey in frontend' => ['frontend', 'backend.1', false];
        yield 'unknown scope' => ['api', 'backend.1', false];
        yield 'missing scope' => [null, 'backend.1', false];
        yield 'unknown handle' => ['backend', 'admin.1', false];
        yield 'invalid ID' => ['backend', 'backend.1suffix', false];
        yield 'nonpositive ID' => ['backend', 'backend.0', false];
    }

    public function testSupportsOnlyLoginResultPostRequests(): void
    {
        $authenticator = new WebauthnAuthenticator($this->createStub(Webauthn::class), $this->createStub(ContaoUserProvider::class), $this->createStub(ContaoUserProvider::class));
        $request = new Request(attributes: ['_route' => 'contao_backend_webauthn_login_result']);

        $this->assertFalse($authenticator->supports($request));
        $request->setMethod('POST');
        $this->assertTrue($authenticator->supports($request));
        $request->attributes->set('_route', 'contao_frontend_webauthn_login_result');
        $this->assertTrue($authenticator->supports($request));
        $request->attributes->set('_route', 'contao_backend_webauthn_registration_result');
        $this->assertFalse($authenticator->supports($request));
    }

    public function testConvertsValidationFailuresToAuthenticationFailures(): void
    {
        $webauthn = $this->createStub(Webauthn::class);
        $webauthn
            ->method('authenticate')
            ->willThrowException(new \RuntimeException('Invalid signature'))
        ;
        $authenticator = new WebauthnAuthenticator($webauthn, $this->createStub(ContaoUserProvider::class), $this->createStub(ContaoUserProvider::class));

        $this->expectException(BadCredentialsException::class);
        $authenticator->authenticate(new Request());
    }
}
