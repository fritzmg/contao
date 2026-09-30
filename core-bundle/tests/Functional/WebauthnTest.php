<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Functional;

use Contao\BackendUser;
use Contao\CoreBundle\Entity\WebauthnCredential;
use Contao\CoreBundle\Repository\WebauthnCredentialRepository;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Contao\CoreBundle\Tests\Fixtures\WebauthnCredentialFixture;
use Contao\FrontendUser;
use Contao\System;
use Contao\TestCase\FunctionalTestCase;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Types\Type;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bridge\Doctrine\ManagerRegistry;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

class WebauthnTest extends FunctionalTestCase
{
    public function testCredentialMappingAndExistingStorageFormatsWorkWithoutTheBundle(): void
    {
        self::bootKernel();
        $container = self::getContainer();
        $metadata = $container->get('doctrine.orm.entity_manager')->getClassMetadata(WebauthnCredential::class);

        $this->assertSame('webauthn_credentials', $metadata->getTableName());

        foreach (['publicKeyCredentialId', 'credentialPublicKey', 'userHandle', 'counter', 'backupEligible', 'backupStatus', 'uvInitialized'] as $field) {
            $this->assertTrue($metadata->hasField($field));
        }

        $platform = new MySQLPlatform();
        $bytes = "\0\xff\x80credential";
        $this->assertSame(base64_encode($bytes), Type::getType('base64')->convertToDatabaseValue($bytes, $platform));
        $this->assertSame($bytes, Type::getType('base64')->convertToPHPValue(base64_encode($bytes), $platform));
        $this->assertInstanceOf(EmptyTrustPath::class, Type::getType('trust_path')->convertToPHPValue('[]', $platform));
        $this->assertSame('00000000-0000-0000-0000-000000000000', (string) Type::getType('aaguid')->convertToPHPValue('00000000-0000-0000-0000-000000000000', $platform));
        $this->assertArrayNotHasKey('WebauthnBundle', $container->getParameter('kernel.bundles'));
    }

    public function testPersistsAndReloadsCredentialsAndTheirVerificationState(): void
    {
        self::bootKernel();
        $configuration = self::getContainer()->get('doctrine.orm.entity_manager')->getConfiguration();
        $manager = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $configuration);
        (new SchemaTool($manager))->createSchema([$manager->getClassMetadata(WebauthnCredential::class)]);
        $registry = $this->createStub(ManagerRegistry::class);
        $registry
            ->method('getManagerForClass')
            ->willReturn($manager)
        ;
        $repository = new WebauthnCredentialRepository($registry);
        $fixture = new WebauthnCredentialFixture();
        $record = new CredentialRecord(
            $fixture->credential->publicKeyCredentialId,
            'public-key',
            ['internal'],
            'none',
            new EmptyTrustPath(),
            $fixture->credential->aaguid,
            $fixture->credential->credentialPublicKey,
            'backend.1',
            42,
            ['name' => 'Test'],
            true,
            true,
            true,
        );
        $repository->saveCredentialSource($record);
        $manager->clear();
        $loaded = $repository->findOneByCredentialId($record->publicKeyCredentialId);

        $this->assertInstanceOf(WebauthnCredential::class, $loaded);
        $this->assertSame($record->credentialPublicKey, $loaded->credentialPublicKey);
        $this->assertSame('backend.1', $loaded->userHandle);
        $this->assertSame(42, $loaded->counter);
        $this->assertSame(['name' => 'Test'], $loaded->otherUI);
        $this->assertTrue($loaded->backupEligible);
        $this->assertTrue($loaded->backupStatus);
        $this->assertTrue($loaded->uvInitialized);
        $loaded->counter = 43;
        $repository->saveCredentialSource($loaded);
        $manager->clear();
        $this->assertSame(43, $repository->findOneByCredentialId($record->publicKeyCredentialId)->counter);
    }

    #[DataProvider('scopes')]
    public function testOnlyAuthenticatesEnabledUsersInTheCredentialsScope(string $scope, bool $disabled): void
    {
        $client = self::createClient();
        $client->disableReboot();

        $container = self::getContainer();
        System::setContainer($container);
        $fixture = new WebauthnCredentialFixture($scope.'.1');
        $repository = $this->createMock(WebauthnCredentialRepository::class);
        $repository
            ->expects($disabled ? $this->once() : $this->exactly(2))
            ->method('findOneByCredentialId')
            ->willReturn($fixture->credential)
        ;

        $repository
            ->expects($this->once())
            ->method('saveCredentialSource')
        ;
        $container->set('contao.repository.webauthn_credential', $repository);

        foreach (['backend' => BackendUser::class, 'frontend' => FrontendUser::class] as $providerScope => $class) {
            $user = $this->createStub($class);
            $user
                ->method('getPasskeyUserHandle')
                ->willReturn($providerScope.'.1')
            ;

            $user
                ->method('getUserIdentifier')
                ->willReturn('admin')
            ;

            $user
                ->method('getRoles')
                ->willReturn(['backend' === $providerScope ? 'ROLE_ADMIN' : 'ROLE_MEMBER'])
            ;

            $user
                ->method('__get')
                ->willReturnMap([['login', true], ['disable', $disabled], ['start', ''], ['stop', '']])
            ;
            $provider = $this->createMock(ContaoUserProvider::class);
            $provider
                ->expects($this->never())
                ->method('loadUserByIdentifier')
            ;

            $provider
                ->expects($scope === $providerScope ? $this->once() : $this->never())
                ->method('loadUserById')
                ->with(1)
                ->willReturn($user)
            ;
            $container->set('contao.security.'.$providerScope.'_user_provider', $provider);
        }

        $client->request('POST', 'https://example.com/_contao/webauthn/'.$scope.'/login/options', server: ['CONTENT_TYPE' => 'application/json'], content: '{}');
        $this->assertResponseIsSuccessful();
        $options = json_decode($client->getResponse()->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $client->request('POST', 'https://example.com/_contao/webauthn/'.$scope.'/login/result', server: ['CONTENT_TYPE' => 'application/json'], content: $fixture->assertion($options));

        if ($disabled) {
            $this->assertResponseStatusCodeSame(401);
            $this->assertNull($container->get('security.token_storage')->getToken());

            return;
        }

        $this->assertResponseIsSuccessful();
        $this->assertSame(['status' => 'ok'], json_decode($client->getResponse()->getContent(), true, flags: JSON_THROW_ON_ERROR));
        $token = $container->get('security.token_storage')->getToken();
        $this->assertInstanceOf('backend' === $scope ? BackendUser::class : FrontendUser::class, $token->getUser());

        $otherScope = 'backend' === $scope ? 'frontend' : 'backend';
        $client->request('POST', 'https://example.com/_contao/webauthn/'.$otherScope.'/login/options', server: ['CONTENT_TYPE' => 'application/json'], content: '{}');
        $this->assertResponseIsSuccessful();
        $options = json_decode($client->getResponse()->getContent(), true, flags: JSON_THROW_ON_ERROR);
        $client->request('POST', 'https://example.com/_contao/webauthn/'.$otherScope.'/login/result', server: ['CONTENT_TYPE' => 'application/json'], content: $fixture->assertion($options));

        $this->assertResponseStatusCodeSame(401);
        $this->assertSame(['status' => 'error'], json_decode($client->getResponse()->getContent(), true, flags: JSON_THROW_ON_ERROR));
    }

    public static function scopes(): iterable
    {
        yield 'backend' => ['backend', false];
        yield 'frontend' => ['frontend', false];
        yield 'disabled backend user' => ['backend', true];
        yield 'disabled frontend user' => ['frontend', true];
    }
}
