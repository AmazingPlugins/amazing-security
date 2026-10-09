<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\BlockList;
use AmazingPlugins\Security\Free\TrafficGuard\Examples;
use PHPUnit\Framework\TestCase;

final class ExamplesTest extends TestCase {
	public function test_recommended_lines_can_be_saved_for_a_normal_admin_request(): void {
		$list    = new BlockList();
		$packs   = array(
			'host'     => Examples::hostnames(),
			'agent'    => Examples::agents(),
			'referrer' => Examples::referrers(),
		);
		$current = array(
			'host'     => '127.0.0.1',
			'agent'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
			'referrer' => 'https://127.0.0.1:18890/wp-admin/admin.php?page=amsec-traffic-guard',
		);
		foreach ( $packs as $kind => $lines ) {
			self::assertNotSame( array(), $lines );
			self::assertLessThanOrEqual( BlockList::MAX_ENTRIES, count( $lines ) );
			foreach ( $lines as $line ) {
				$length = function_exists( 'mb_strlen' ) ? mb_strlen( $line ) : strlen( $line );
				self::assertLessThanOrEqual( BlockList::MAX_LENGTH, $length );
				self::assertStringNotContainsString( 'safe', strtolower( $line ) );
			}
			$prepared = $list->prepare( implode( "\n", $lines ), $kind, $current[ $kind ] );
			self::assertTrue( $prepared['ok'], $kind );
			self::assertSame( $lines, $list->lines( $prepared['value'] ) );
		}
		self::assertNotContains( '127.0.0.1', Examples::hostnames() );
		self::assertNotContains( 'localhost', Examples::hostnames() );
	}
}
