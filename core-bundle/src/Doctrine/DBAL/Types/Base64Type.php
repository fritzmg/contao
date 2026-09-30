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

/**
 * Keeps the base64 storage format of existing passkey IDs and public keys.
 *
 * @internal
 */
class Base64Type extends TextType
{
    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): string|null
    {
        return null === $value ? null : base64_encode($value);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): string|null
    {
        return null === $value ? null : base64_decode($value, true);
    }

    public function getName(): string
    {
        return 'base64';
    }
}
