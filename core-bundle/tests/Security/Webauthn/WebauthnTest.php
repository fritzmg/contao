<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Security\Webauthn;

use Contao\BackendUser;
use Contao\CoreBundle\Entity\WebauthnCredential;
use Contao\CoreBundle\Repository\WebauthnCredentialRepository;
use Contao\CoreBundle\Security\Webauthn\Webauthn;
use Contao\CoreBundle\Tests\Fixtures\WebauthnCredentialFixture;
use Contao\FrontendUser;
use Contao\User;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Webauthn\CredentialRecord;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\Exception\CounterException;

class WebauthnTest extends TestCase
{
    #[DataProvider('scopes')]
    public function testValidatesASignedAssertionAndSavesTheCounter(string $scope): void
    {
        $fixture = new WebauthnCredentialFixture($scope.'.1');
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('findOneByCredentialId')
            ->with($fixture->credential->publicKeyCredentialId)
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->once())
            ->method('saveCredentialSource')
            ->with($this->callback(static fn (WebauthnCredential $credential): bool => 1 === $credential->counter))
        ;

        $webauthn = new Webauthn($repository);
        $request = $this->request($scope);
        $options = json_decode($webauthn->createRequestOptions($request), true, flags: JSON_THROW_ON_ERROR);

        $this->assertSame($fixture->credential, $webauthn->authenticate($this->request($scope, $fixture->assertion($options), $request->getSession())));

        $this->expectException(BadCredentialsException::class);
        $webauthn->authenticate($this->request($scope, $fixture->assertion($options), $request->getSession()));
    }

    #[DataProvider('scopes')]
    public function testRejectsACredentialFromTheOtherScope(string $scope): void
    {
        $fixture = new WebauthnCredentialFixture(('backend' === $scope ? 'frontend' : 'backend').'.1');
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('findOneByCredentialId')
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->never())
            ->method('saveCredentialSource')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request($scope);
        $options = json_decode($webauthn->createRequestOptions($request), true, flags: JSON_THROW_ON_ERROR);

        $this->expectException(BadCredentialsException::class);
        $webauthn->authenticate($this->request($scope, $fixture->assertion($options), $request->getSession()));
    }

    #[DataProvider('invalidAssertions')]
    public function testRejectsInvalidAssertions(string $failure): void
    {
        $fixture = new WebauthnCredentialFixture();
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('findOneByCredentialId')
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->never())
            ->method('saveCredentialSource')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request('backend');
        $options = json_decode($webauthn->createRequestOptions($request), true, flags: JSON_THROW_ON_ERROR);

        if ('challenge' === $failure) {
            $options['challenge'] = WebauthnCredentialFixture::encode(random_bytes(32));
        }

        if ('rpId' === $failure) {
            $options['rpId'] = 'attacker.example';
        }

        $assertion = $fixture->assertion(
            $options,
            origin: 'origin' === $failure ? 'https://attacker.example' : 'https://example.com',
            flags: 'verification' === $failure ? 1 : ('presence' === $failure ? 4 : 5),
            userHandle: 'owner' === $failure ? 'backend.2' : ('missing owner' === $failure ? '' : null),
        );

        if ('signature' === $failure) {
            $data = json_decode($assertion, true, flags: JSON_THROW_ON_ERROR);
            $data['response']['signature'] = WebauthnCredentialFixture::encode(random_bytes(64));
            $assertion = json_encode($data, JSON_THROW_ON_ERROR);
        }

        if ('counter' === $failure) {
            $fixture->credential->counter = 1;
        }

        $this->expectException('counter' === $failure ? CounterException::class : AuthenticatorResponseVerificationException::class);
        $webauthn->authenticate($this->request('backend', $assertion, $request->getSession()));
    }

    public static function invalidAssertions(): iterable
    {
        foreach (['challenge', 'rpId', 'origin', 'verification', 'presence', 'owner', 'missing owner', 'signature', 'counter'] as $failure) {
            yield $failure => [$failure];
        }
    }

    #[DataProvider('missingChallenges')]
    public function testRejectsAnUnavailableChallenge(string $failure): void
    {
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->never())
            ->method('findOneByCredentialId')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request('backend');
        $webauthn->createRequestOptions($request);

        if ('expired' === $failure) {
            $data = $request->getSession()->get('_contao_webauthn.backend.login');
            $data['expires'] = time() - 1;
            $request->getSession()->set('_contao_webauthn.backend.login', $data);
        }

        $result = $this->request('scope' === $failure ? 'frontend' : 'backend', session: 'session' === $failure ? null : $request->getSession());

        if ('origin' === $failure) {
            $result->headers->set('host', 'other.example.com');
        }

        $this->expectException(BadCredentialsException::class);
        $webauthn->authenticate($result);
    }

    public static function missingChallenges(): iterable
    {
        foreach (['scope', 'session', 'expired', 'origin'] as $failure) {
            yield $failure => [$failure];
        }
    }

    #[DataProvider('scopes')]
    public function testRegistersACredentialForTheAuthenticatedUser(string $scope): void
    {
        $fixture = new WebauthnCredentialFixture($scope.'.1');
        $user = $this->user($scope);
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('getAllForUser')
            ->with($user)
            ->willReturn([$fixture->credential])
        ;

        $repository
            ->expects($this->once())
            ->method('findOneByCredentialId')
            ->with($fixture->credential->publicKeyCredentialId)
            ->willReturn(null)
        ;

        $repository
            ->expects($this->once())
            ->method('saveCredentialSource')
            ->with($this->callback(static fn (CredentialRecord $record): bool => $scope.'.1' === $record->userHandle && $record->uvInitialized))
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request($scope);
        $options = json_decode($webauthn->createCreationOptions($request, $user), true, flags: JSON_THROW_ON_ERROR);

        $this->assertSame('example.com', $options['rp']['id']);
        $this->assertSame('required', $options['authenticatorSelection']['userVerification']);
        $this->assertSame('required', $options['authenticatorSelection']['residentKey']);
        $this->assertSame(WebauthnCredentialFixture::encode($fixture->credential->publicKeyCredentialId), $options['excludeCredentials'][0]['id']);

        $webauthn->register($this->request($scope, $fixture->attestation($options), $request->getSession()), $user);
    }

    public function testRejectsRegistrationAfterTheUserChanges(): void
    {
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('getAllForUser')
            ->willReturn([])
        ;

        $repository
            ->expects($this->never())
            ->method('saveCredentialSource')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request('backend');
        $webauthn->createCreationOptions($request, $this->user('backend'));

        $this->expectException(BadCredentialsException::class);
        $webauthn->register($this->request('backend', session: $request->getSession()), $this->user('backend', 'backend.2'));
    }

    public function testRequiresJsonForOptions(): void
    {
        $webauthn = new Webauthn($this->createStub(WebauthnCredentialRepository::class));
        $request = $this->request('backend');
        $request->headers->set('Content-Type', 'text/plain');

        $this->expectException(BadCredentialsException::class);
        $webauthn->createRequestOptions($request);
    }

    #[DataProvider('invalidRegistrations')]
    public function testCannotOverwriteAnExistingCredentialOrChangeItsId(string $failure): void
    {
        $fixture = new WebauthnCredentialFixture();
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('getAllForUser')
            ->willReturn([])
        ;

        $repository
            ->expects('duplicate' === $failure ? $this->once() : $this->never())
            ->method('findOneByCredentialId')
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->never())
            ->method('saveCredentialSource')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request('backend');
        $user = $this->user('backend');
        $options = json_decode($webauthn->createCreationOptions($request, $user), true, flags: JSON_THROW_ON_ERROR);
        $attestation = $fixture->attestation($options);

        if ('id' === $failure) {
            $data = json_decode($attestation, true, flags: JSON_THROW_ON_ERROR);
            $data['id'] = $data['rawId'] = WebauthnCredentialFixture::encode(random_bytes(32));
            $attestation = json_encode($data, JSON_THROW_ON_ERROR);
        }

        $this->expectException(BadCredentialsException::class);
        $webauthn->register($this->request('backend', $attestation, $request->getSession()), $user);
    }

    public static function invalidRegistrations(): iterable
    {
        yield 'duplicate' => ['duplicate'];
        yield 'id' => ['id'];
    }

    public function testLoginCannotUseTheRegistrationChallenge(): void
    {
        $fixture = new WebauthnCredentialFixture();
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($this->once())
            ->method('getAllForUser')
            ->willReturn([])
        ;

        $repository
            ->expects($this->once())
            ->method('findOneByCredentialId')
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->never())
            ->method('saveCredentialSource')
        ;
        $webauthn = new Webauthn($repository);
        $request = $this->request('backend');
        $login = json_decode($webauthn->createRequestOptions($request), true, flags: JSON_THROW_ON_ERROR);
        $registration = json_decode($webauthn->createCreationOptions($request, $this->user('backend')), true, flags: JSON_THROW_ON_ERROR);
        $this->assertNotSame($login['challenge'], $registration['challenge']);
        $login['challenge'] = $registration['challenge'];

        $this->expectException(AuthenticatorResponseVerificationException::class);
        $webauthn->authenticate($this->request('backend', $fixture->assertion($login), $request->getSession()));
    }

    public static function scopes(): iterable
    {
        yield 'backend' => ['backend'];
        yield 'frontend' => ['frontend'];
    }

    private function request(string $scope, string $body = '{}', SessionInterface|null $session = null): Request
    {
        $request = Request::create('https://example.com/', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: $body);
        $request->attributes->set('_scope', $scope);
        $request->setSession($session ?? new Session(new MockArraySessionStorage()));

        return $request;
    }

    private function user(string $scope, string|null $handle = null): User
    {
        $user = $this->createStub('backend' === $scope ? BackendUser::class : FrontendUser::class);
        $user
            ->method('getPasskeyUserHandle')
            ->willReturn($handle ?? $scope.'.1')
        ;

        $user
            ->method('getUserIdentifier')
            ->willReturn('admin')
        ;

        $user
            ->method('getDisplayName')
            ->willReturn('Admin')
        ;

        return $user;
    }
}
