<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\Tests\EventListener;

use Contao\CoreBundle\EventListener\VirtualFieldsMappingListener;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\CoreBundle\Tests\TestCase;
use Contao\DC_File;
use Contao\DC_Table;
use Contao\FormPassword;
use Contao\TextField;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;

class VirtualFieldsMappingListenerTest extends TestCase
{
    protected function setUp(): void
    {
        $GLOBALS['BE_FFL'] = ['text' => TextField::class, 'password' => FormPassword::class];

        parent::setUp();
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_FFL']);

        parent::tearDown();
    }

    #[DataProvider('virtualFieldsMappingProvider')]
    public function testVirtualFieldsMapping(array $fields, array $expected, string $dc = DC_Table::class): void
    {
        $GLOBALS['TL_DCA']['tl_foobar'] = [
            'config' => [
                'dataContainer' => $dc,
            ],
            'fields' => $fields,
            'palettes' => ['default' => 'foobar'],
        ];

        (new VirtualFieldsMappingListener($this->getFramework()))('tl_foobar');

        $this->assertSame($expected, $GLOBALS['TL_DCA']['tl_foobar']['fields']);

        unset($GLOBALS['TL_DCA']);
    }

    public static function virtualFieldsMappingProvider(): iterable
    {
        $defaultSql = ['type' => 'json', 'length' => MySQLPlatform::LENGTH_LIMIT_MEDIUMTEXT, 'notnull' => false];
        $textSql = ['type' => 'text', 'length' => MySQLPlatform::LENGTH_LIMIT_MEDIUMTEXT, 'notnull' => false];

        yield 'Adds saveTo and virtualTarget and sql' => [
            [
                'foobar' => ['inputType' => 'text'],
            ],
            [
                'foobar' => ['inputType' => 'text', 'saveTo' => 'jsonData'],
                'jsonData' => ['virtualTarget' => true, 'sql' => $defaultSql],
            ],
        ];

        yield 'Does not change saveTo' => [
            [
                'foobar' => ['inputType' => 'text', 'saveTo' => 'fooData'],
            ],
            [
                'foobar' => ['inputType' => 'text', 'saveTo' => 'fooData'],
                'fooData' => ['virtualTarget' => true, 'sql' => $defaultSql],
            ],
        ];

        yield 'Does not change sql' => [
            [
                'foobar' => ['inputType' => 'text'],
                'jsonData' => ['sql' => $textSql],
            ],
            [
                'foobar' => ['inputType' => 'text', 'saveTo' => 'jsonData'],
                'jsonData' => ['sql' => $textSql, 'virtualTarget' => true],
            ],
        ];

        yield 'Does not auto map with existing sql config' => [
            [
                'foobar' => ['inputType' => 'text', 'sql' => []],
            ],
            [
                'foobar' => ['inputType' => 'text', 'sql' => []],
            ],
        ];

        yield 'Does not auto map with existing input_field_callback' => [
            [
                'foobar' => ['inputType' => 'text', 'input_field_callback' => []],
            ],
            [
                'foobar' => ['inputType' => 'text', 'input_field_callback' => []],
            ],
        ];

        yield 'Does not auto map with existing save_callback' => [
            [
                'foobar' => ['inputType' => 'text', 'save_callback' => []],
            ],
            [
                'foobar' => ['inputType' => 'text', 'save_callback' => []],
            ],
        ];

        yield 'Does not auto map for non-DC_Table based DCAs' => [
            [
                'foobar' => ['inputType' => 'text'],
            ],
            [
                'foobar' => ['inputType' => 'text'],
            ],
            DC_File::class,
        ];

        yield 'Does not auto map for widgets that do not submit input' => [
            [
                'foobar' => ['inputType' => 'password'],
            ],
            [
                'foobar' => ['inputType' => 'password'],
            ],
        ];
    }

    public function testDoesNotMapForNonEditableDcas(): void
    {
        $GLOBALS['TL_DCA']['tl_foobar'] = [
            'config' => [
                'dataContainer' => DC_Table::class,
                'notEditable' => true,
            ],
            'fields' => [
                'foobar' => [
                    'inputType' => 'text',
                ],
            ],
            'palettes' => ['default' => 'foobar'],
        ];

        (new VirtualFieldsMappingListener($this->getFramework()))('tl_foobar');

        /** @phpstan-ignore method.alreadyNarrowedType */
        $this->assertSame(['foobar' => ['inputType' => 'text']], $GLOBALS['TL_DCA']['tl_foobar']['fields']);

        unset($GLOBALS['TL_DCA']);
    }

    public function testDoesNotMapForDcasWithoutPalettes(): void
    {
        $GLOBALS['TL_DCA']['tl_foobar'] = [
            'config' => [
                'dataContainer' => DC_Table::class,
            ],
            'fields' => [
                'foobar' => [
                    'inputType' => 'text',
                ],
            ],
        ];

        (new VirtualFieldsMappingListener($this->getFramework()))('tl_foobar');

        /** @phpstan-ignore method.alreadyNarrowedType */
        $this->assertSame(['foobar' => ['inputType' => 'text']], $GLOBALS['TL_DCA']['tl_foobar']['fields']);

        unset($GLOBALS['TL_DCA']);
    }

    private function getFramework(): ContaoFramework&Stub
    {
        $framework = $this->createStub(ContaoFramework::class);
        $framework
            ->method('createInstance')
            ->willReturnCallback(
                function (string $key): Stub {
                    $widget = $this->createStub($key);
                    $widget
                        ->method('submitInput')
                        ->willReturn(TextField::class === $key ? true : false)
                    ;

                    return $widget;
                },
            )
        ;

        return $framework;
    }
}
