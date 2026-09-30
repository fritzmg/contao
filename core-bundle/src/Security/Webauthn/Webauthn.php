<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Security\Webauthn;

use Contao\CoreBundle\Entity\WebauthnCredential;
use Contao\CoreBundle\Repository\WebauthnCredentialRepository;
use Contao\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * @internal
 */
class Webauthn
{
    private const CHALLENGE_LIFETIME = 300;

    private readonly SerializerInterface $serializer;

    public function __construct(private readonly WebauthnCredentialRepository $repository)
    {
        $this->serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create();
    }

    public function createRequestOptions(Request $request): string
    {
        return $this->storeOptions($request, 'login', PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            rpId: $request->getHost(),
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: 60000,
        ));
    }

    public function createCreationOptions(Request $request, User $user): string
    {
        $this->checkUserHandle($request, $user->getPasskeyUserHandle());

        return $this->storeOptions($request, 'registration', PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', $request->getHost()),
            PublicKeyCredentialUserEntity::create($user->getUserIdentifier(), $user->getPasskeyUserHandle(), $user->getDisplayName()),
            random_bytes(32),
            [PublicKeyCredentialParameters::create('public-key', -7), PublicKeyCredentialParameters::create('public-key', -257)],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: array_map(static fn (WebauthnCredential $credential): PublicKeyCredentialDescriptor => $credential->getPublicKeyCredentialDescriptor(), $this->repository->getAllForUser($user)),
            timeout: 60000,
        ));
    }

    public function authenticate(Request $request): WebauthnCredential
    {
        $options = $this->consumeOptions($request, 'login', PublicKeyCredentialRequestOptions::class);
        $publicKeyCredential = $this->loadCredential($request);

        if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            throw new BadCredentialsException('Expected a passkey assertion.');
        }

        $credential = $this->repository->findOneByCredentialId($publicKeyCredential->rawId);

        if (!$credential) {
            throw new BadCredentialsException('Unknown passkey.');
        }

        // The stored owner determines the account and scope, never a submitted username.
        $this->checkUserHandle($request, $credential->userHandle);

        $validator = AuthenticatorAssertionResponseValidator::create($this->createCeremonyFactory($request)->requestCeremony());
        $validator->check($credential, $publicKeyCredential->response, $options, $request->getHost(), null);

        $this->repository->saveCredentialSource($credential);

        return $credential;
    }

    public function register(Request $request, User $user): void
    {
        $options = $this->consumeOptions($request, 'registration', PublicKeyCredentialCreationOptions::class);

        $this->checkUserHandle($request, $user->getPasskeyUserHandle());

        if ($options->user->id !== $user->getPasskeyUserHandle()) {
            throw new BadCredentialsException('The passkey registration belongs to another user.');
        }

        $publicKeyCredential = $this->loadCredential($request);

        if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            throw new BadCredentialsException('Expected a passkey attestation.');
        }

        $validator = AuthenticatorAttestationResponseValidator::create($this->createCeremonyFactory($request)->creationCeremony());
        $credential = $validator->check($publicKeyCredential->response, $options, $request->getHost());

        if ($credential->publicKeyCredentialId !== $publicKeyCredential->rawId || $this->repository->findOneByCredentialId($credential->publicKeyCredentialId)) {
            throw new BadCredentialsException('The passkey already exists or its ID is invalid.');
        }

        $this->repository->saveCredentialSource($credential);
    }

    private function storeOptions(Request $request, string $ceremony, PublicKeyCredentialOptions $options): string
    {
        $this->checkContentType($request);

        $json = $this->serializer->serialize($options, 'json');
        $request->getSession()->set(
            $this->getSessionKey($request, $ceremony),
            [
                'options' => $json,
                'expires' => time() + self::CHALLENGE_LIFETIME,
                'origin' => $request->getSchemeAndHttpHost(),
            ],
        );

        return $json;
    }

    /**
     * @template T of PublicKeyCredentialOptions
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private function consumeOptions(Request $request, string $ceremony, string $class): PublicKeyCredentialOptions
    {
        $this->checkContentType($request);

        // Consume before validation so that failed ceremonies cannot be retried or replayed.
        $data = $request->getSession()->remove($this->getSessionKey($request, $ceremony));

        if (null === $data || $data['expires'] <= time() || $data['origin'] !== $request->getSchemeAndHttpHost()) {
            throw new BadCredentialsException('The passkey challenge is missing or expired.');
        }

        return $this->serializer->deserialize($data['options'], $class, 'json');
    }

    private function loadCredential(Request $request): PublicKeyCredential
    {
        return $this->serializer->deserialize($request->getContent(), PublicKeyCredential::class, 'json');
    }

    private function checkContentType(Request $request): void
    {
        // JSON requires a CORS preflight, which also protects these endpoints against CSRF.
        if ('json' !== $request->getContentTypeFormat()) {
            throw new BadCredentialsException('Passkey requests must use JSON.');
        }
    }

    private function checkUserHandle(Request $request, string $userHandle): void
    {
        $scope = $request->attributes->get('_scope');

        if (!\in_array($scope, ['backend', 'frontend'], true) || !preg_match('/^'.$scope.'\.[1-9][0-9]*$/D', $userHandle)) {
            throw new BadCredentialsException('The passkey belongs to another scope.');
        }
    }

    private function getSessionKey(Request $request, string $ceremony): string
    {
        $scope = $request->attributes->get('_scope');

        if (!\in_array($scope, ['backend', 'frontend'], true)) {
            throw new BadCredentialsException('Unknown passkey scope.');
        }

        return '_contao_webauthn.'.$scope.'.'.$ceremony;
    }

    private function createCeremonyFactory(Request $request): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([$request->getSchemeAndHttpHost()]);

        return $factory;
    }
}
