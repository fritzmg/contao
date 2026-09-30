<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Controller;

use Contao\BackendUser;
use Contao\CoreBundle\Controller\WebauthnController;
use Contao\CoreBundle\Security\Webauthn\Webauthn;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class WebauthnControllerTest extends TestCase
{
    #[DataProvider('registrationActions')]
    public function testRequiresFullAuthenticationBeforeStartingOrCompletingRegistration(string $action): void
    {
        $webauthn = $this->createMock(Webauthn::class);
        $webauthn
            ->expects($this->never())
            ->method('createCreationOptions')
        ;

        $webauthn
            ->expects($this->never())
            ->method('register')
        ;
        $checker = $this->createMock(AuthorizationCheckerInterface::class);
        $checker
            ->expects($this->once())
            ->method('isGranted')
            ->with('IS_AUTHENTICATED_FULLY')
            ->willReturn(false)
        ;
        $container = new Container();
        $container->set('security.authorization_checker', $checker);

        $controller = new WebauthnController($webauthn);
        $controller->setContainer($container);

        $this->expectException(AccessDeniedException::class);
        $controller->$action(new Request());
    }

    public function testUsesTheCurrentUserForRegistration(): void
    {
        $user = $this->createStub(BackendUser::class);
        $request = new Request();
        $webauthn = $this->createMock(Webauthn::class);
        $webauthn
            ->expects($this->once())
            ->method('createCreationOptions')
            ->with($request, $user)
            ->willReturn('{"challenge":"test"}')
        ;

        $webauthn
            ->expects($this->once())
            ->method('register')
            ->with($request, $user)
        ;
        $checker = $this->createStub(AuthorizationCheckerInterface::class);
        $checker
            ->method('isGranted')
            ->willReturn(true)
        ;
        $storage = new TokenStorage();
        $storage->setToken(new UsernamePasswordToken($user, 'contao_backend', []));

        $container = new Container();
        $container->set('security.authorization_checker', $checker);
        $container->set('security.token_storage', $storage);

        $controller = new WebauthnController($webauthn);
        $controller->setContainer($container);

        $this->assertSame(['status' => 'ok', 'challenge' => 'test'], json_decode($controller->registrationOptions($request)->getContent(), true, flags: JSON_THROW_ON_ERROR));
        $this->assertSame(['status' => 'ok'], json_decode($controller->registrationResult($request)->getContent(), true, flags: JSON_THROW_ON_ERROR));
    }

    public static function registrationActions(): iterable
    {
        yield 'options' => ['registrationOptions'];
        yield 'result' => ['registrationResult'];
    }
}
