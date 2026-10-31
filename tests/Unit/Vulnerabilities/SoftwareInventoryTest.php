<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Vulnerabilities\WordPressSoftwareInventory;
use PHPUnit\Framework\TestCase;

final class SoftwareInventoryTest extends TestCase {
	public function test_only_trusted_repository_identifiers_are_eligible(): void {
		$inventory = new WordPressSoftwareInventory(
			static fn (): array => array(
				'core'    => array(
					'version' => '6.9.4',
					'locale'  => 'en_US',
				),
				'plugins' => array(
					array(
						'file'             => 'akismet/akismet.php',
						'version'          => '5.3',
						'update_uri'       => '',
						'repository_slug'  => 'akismet',
						'verified_release' => true,
					),
					array(
						'file'            => 'akismet/custom.php',
						'version'         => '5.3',
						'update_uri'      => '',
						'repository_slug' => 'akismet',
					),
					array(
						'file'            => 'paid/paid.php',
						'version'         => '2.0',
						'update_uri'      => 'https://vendor.example',
						'repository_slug' => 'paid',
					),
					array(
						'file'            => 'other/other.php',
						'version'         => '1.0',
						'update_uri'      => '',
						'repository_slug' => '',
					),
				),
				'themes'  => array(
					array(
						'slug'             => 'twentytwentyfive',
						'version'          => '1.2',
						'repository_slug'  => 'twentytwentyfive',
						'verified_release' => true,
					),
					array(
						'slug'            => 'custom',
						'version'         => '1.0',
						'repository_slug' => '',
					),
				),
			)
		);
		$items     = $inventory->collect();
		self::assertCount( 7, $items );
		self::assertSame( array( true, true, false, false, false, true, false ), array_map( static fn ( $item ): bool => $item->eligible, $items ) );
		self::assertSame( array( 'wordpress', 'akismet', 'akismet', 'paid', 'other', 'twentytwentyfive', 'custom' ), array_map( static fn ( $item ): string => $item->slug, $items ) );
		self::assertSame( 'plugin', $items[2]->type );
	}

	public function test_missing_or_malformed_versions_are_unknown_and_inventory_is_bounded(): void {
		$plugins = array();
		for ( $i = 0; $i < 1100; ++$i ) {
			$plugins[] = array(
				'file'            => 'pkg-' . $i . '/main.php',
				'version'         => '',
				'repository_slug' => 'pkg-' . $i,
			);
		}
		$inventory = new WordPressSoftwareInventory(
			static fn (): array => array(
				'core'    => array( 'version' => 'bad version' ),
				'plugins' => $plugins,
				'themes'  => array(),
			)
		);
		$items     = $inventory->collect();
		self::assertCount( 1000, $items );
		self::assertFalse( $items[0]->eligible );
		self::assertFalse( $items[1]->eligible );
		self::assertFalse( $inventory->complete() );
		self::assertStringNotContainsString( '/var/', json_encode( array_map( static fn ( $item ): array => $item->toArray(), $items ) ) );
	}
}
