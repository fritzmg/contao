<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\Fixtures;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Contao\CoreBundle\Entity\WebauthnCredential;
use Symfony\Component\Uid\Uuid;
use Webauthn\TrustPath\EmptyTrustPath;

class WebauthnCredentialFixture
{
    public readonly WebauthnCredential $credential;

    private readonly \OpenSSLAsymmetricKey $key;

    public function __construct(string $userHandle = 'backend.1')
    {
        $this->key = openssl_pkey_get_private(<<<'PEM'
            -----BEGIN EC PRIVATE KEY-----
            MDECAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAoGCCqGSM49AwEH
            -----END EC PRIVATE KEY-----
            PEM);
        $details = openssl_pkey_get_details($this->key);
        $publicKey = MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)))
        ;

        $this->credential = new WebauthnCredential(
            random_bytes(32),
            'public-key',
            ['internal'],
            'none',
            new EmptyTrustPath(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            (string) $publicKey,
            $userHandle,
            0,
        );
    }

    public function assertion(array $options, string $origin = 'https://example.com', int $flags = 5, string|null $userHandle = null, int $counter = 1): string
    {
        $clientData = json_encode(['type' => 'webauthn.get', 'challenge' => $options['challenge'], 'origin' => $origin], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', $options['rpId'], true).\chr($flags).pack('N', $counter);
        openssl_sign($authData.hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);

        return $this->response([
            'clientDataJSON' => self::encode($clientData),
            'authenticatorData' => self::encode($authData),
            'signature' => self::encode($signature),
            'userHandle' => self::encode($userHandle ?? $this->credential->userHandle),
        ]);
    }

    public function attestation(array $options): string
    {
        $clientData = json_encode(['type' => 'webauthn.create', 'challenge' => $options['challenge'], 'origin' => 'https://example.com'], JSON_THROW_ON_ERROR);
        $authData = hash('sha256', $options['rp']['id'], true)."\x45".pack('N', 0)
            .$this->credential->aaguid->toBinary().pack('n', \strlen($this->credential->publicKeyCredentialId))
            .$this->credential->publicKeyCredentialId.$this->credential->credentialPublicKey;

        $attestation = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData))
        ;

        return $this->response([
            'clientDataJSON' => self::encode($clientData),
            'attestationObject' => self::encode((string) $attestation),
            'transports' => ['internal'],
        ]);
    }

    public static function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function response(array $response): string
    {
        return json_encode(
            [
                'id' => self::encode($this->credential->publicKeyCredentialId),
                'rawId' => self::encode($this->credential->publicKeyCredentialId),
                'type' => 'public-key',
                'response' => $response,
            ],
            JSON_THROW_ON_ERROR,
        );
    }
}
