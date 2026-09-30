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
use Doctrine\DBAL\Types\TextType;
use Symfony\Component\Uid\Uuid;

/**
 * @internal
 */
class AaguidType extends TextType
{
    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): string|null
    {
        return null === $value ? null : (string) $value;
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): Uuid|null
    {
        return null === $value || $value instanceof Uuid ? $value : Uuid::fromString($value);
    }

    public function getName(): string
    {
        return 'aaguid';
    }
}
