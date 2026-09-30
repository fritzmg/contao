<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Doctrine\DBAL\Types;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\JsonType;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\TrustPath\TrustPath;

/**
 * @internal
 */
class TrustPathType extends JsonType
{
    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): string|null
    {
        if (null === $value || \is_string($value)) {
            return $value;
        }

        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create()->serialize($value, 'json');
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): TrustPath|null
    {
        if (null === $value || $value instanceof TrustPath) {
            return $value;
        }

        return (new WebauthnSerializerFactory(AttestationStatementSupportManager::create()))->create()->deserialize($value, TrustPath::class, 'json');
    }

    public function getName(): string
    {
        return 'trust_path';
    }
}
