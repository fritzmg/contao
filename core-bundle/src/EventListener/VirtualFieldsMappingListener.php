<?php

declare(strict_types=1);

/*
 * This file is part of Contao.
 *
 * (c) Leo Feyer
 *
 * @license LGPL-3.0-or-later
 */

namespace Contao\CoreBundle\EventListener;

use Contao\CoreBundle\DependencyInjection\Attribute\AsHook;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\DataContainer;
use Contao\DC_Table;
use Contao\Widget;
use Doctrine\DBAL\Platforms\MySQLPlatform;

/**
 * Adds "saveTo" automatically to fields without an "sql" definition. Defines
 * "saveTo" targets automatically as "virtualTarget". Adds an "sql" definition
 * automatically to virtual field targets.
 */
#[AsHook('loadDataContainer', priority: -4096)]
class VirtualFieldsMappingListener
{
    /**
     * @var list<Widget>
     */
    private static array $widgets = [];

    public function __construct(
        private readonly ContaoFramework $contaoFramework,
        private readonly string $defaultStorageName = 'jsonData',
    ) {
    }

    public function __invoke(string $table): void
    {
        // Only support auto-mapping for DC_Table
        if (!is_a(DataContainer::getDriverForTable($table), DC_Table::class, true)) {
            return;
        }

        // Ignore any DCAs that are not editable or do not have any palettes
        if (($GLOBALS['TL_DCA'][$table]['config']['notEditable'] ?? null) || !($GLOBALS['TL_DCA'][$table]['palettes'] ?? null)) {
            return;
        }

        $GLOBALS['TL_DCA'][$table]['fields'] = array_map(
            function (array $config): array {
                if (\array_key_exists('sql', $config) || \array_key_exists('saveTo', $config) || \array_key_exists('input_field_callback', $config) || \array_key_exists('save_callback', $config) || !isset($config['inputType'])) {
                    return $config;
                }

                // Check if widget supports input submission
                $submitInput = self::$widgets[$config['inputType']] ?? null;

                if (null === $submitInput) {
                    $class = $GLOBALS['BE_FFL'][$config['inputType']] ?? null;
                    $submitInput = $class && class_exists($class) ? $this->contaoFramework->createInstance($class)->submitInput() : false;
                    self::$widgets[$config['inputType']] = $submitInput;
                }

                if (!$submitInput) {
                    return $config;
                }

                // Automatically save to virtual field in DC_Table
                $config['saveTo'] = $this->defaultStorageName;

                return $config;
            },
            $GLOBALS['TL_DCA'][$table]['fields'],
        );

        // Configure virtual field targets
        foreach (array_unique(array_column($GLOBALS['TL_DCA'][$table]['fields'], 'saveTo')) as $target) {
            $GLOBALS['TL_DCA'][$table]['fields'][$target]['virtualTarget'] = true;

            if (!($GLOBALS['TL_DCA'][$table]['fields'][$target]['sql'] ?? null)) {
                $GLOBALS['TL_DCA'][$table]['fields'][$target]['sql'] = ['type' => 'json', 'length' => MySQLPlatform::LENGTH_LIMIT_MEDIUMTEXT, 'notnull' => false];
            }
        }
    }
}
