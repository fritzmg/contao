<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Entity;

use Contao\CoreBundle\Repository\WebauthnCredentialRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Table;
use Symfony\Component\Uid\Ulid;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\TrustPath;

#[Table(name: 'webauthn_credentials')]
#[Entity(repositoryClass: WebauthnCredentialRepository::class)]
class WebauthnCredential extends CredentialRecord
{
    #[Column(type: 'base64')]
    public string $publicKeyCredentialId;

    #[Column]
    public string $type;

    /**
     * @var list<string>
     */
    #[Column(type: Types::JSON)]
    public array $transports;

    #[Column]
    public string $attestationType;

    #[Column(type: 'trust_path')]
    public TrustPath $trustPath;

    #[Column(type: 'aaguid', length: 36)]
    public Uuid $aaguid;

    #[Column(type: 'base64')]
    public string $credentialPublicKey;

    #[Column]
    public string $userHandle;

    #[Column(type: Types::INTEGER)]
    public int $counter;

    /**
     * @var array<string, mixed>|null
     */
    #[Column(type: Types::JSON, nullable: true)]
    public array|null $otherUI = null;

    #[Column(type: Types::BOOLEAN, nullable: true)]
    public bool|null $backupEligible = null;

    #[Column(type: Types::BOOLEAN, nullable: true)]
    public bool|null $backupStatus = null;

    #[Column(type: Types::BOOLEAN, nullable: true)]
    public bool|null $uvInitialized = null;

    #[Column(type: Types::STRING)]
    public string $name;

    #[Column(type: Types::DATETIME_IMMUTABLE)]
    public readonly \DateTimeImmutable $createdAt;

    #[Id]
    #[Column(unique: true)]
    #[GeneratedValue(strategy: 'NONE')]
    private readonly string $id;

    public function __construct(string $publicKeyCredentialId, string $type, array $transports, string $attestationType, TrustPath $trustPath, Uuid $aaguid, string $credentialPublicKey, string $userHandle, int $counter, array|null $otherUI = null, bool|null $backupEligible = null, bool|null $backupStatus = null, bool|null $uvInitialized = null)
    {
        $this->id = Ulid::generate();
        $this->name = '';
        $this->createdAt = new \DateTimeImmutable();

        parent::__construct($publicKeyCredentialId, $type, $transports, $attestationType, $trustPath, $aaguid, $credentialPublicKey, $userHandle, $counter, $otherUI, $backupEligible, $backupStatus, $uvInitialized);
    }

    public function getId(): string
    {
        return $this->id;
    }
}
