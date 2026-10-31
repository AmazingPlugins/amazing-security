<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\LiveTraffic;
use PHPUnit\Framework\TestCase;

final class LiveTrafficTest extends TestCase {
	public function test_query_strings_are_not_stored(): void {
		$log = new LiveTraffic();
		$row = $log->row(
			array(
				'REMOTE_ADDR'  => '203.0.113.8',
				'REQUEST_URI'  => '/shop/item?password=secret&token=abc',
				'QUERY_STRING' => 'password=secret&token=abc',
				'HTTP_COOKIE'  => 'wordpress_logged_in=secret',
			),
			1700000000
		);
		self::assertSame(
			array(
				'ip'   => '203.0.113.8',
				'path' => '/shop/item',
				'time' => 1700000000,
			),
			$row
		);
		$encoded = json_encode( $row );
		self::assertIsString( $encoded );
		self::assertStringNotContainsString( 'password', $encoded );
		self::assertStringNotContainsString( 'secret', $encoded );
		self::assertStringNotContainsString( '?', (string) $row['path'] );
		self::assertSame( '/read/note', $log->path( '/read/note?x=1#part' ) );
		self::assertSame( '/AZ/file-1.txt', $log->path( '/A Z/file-1.txt?ok=1' ) );
	}

	public function test_oldest_rows_drop_at_the_cap(): void {
		$log  = new LiveTraffic();
		$rows = array();
		for ( $time = 0; $time < LiveTraffic::CAP; $time++ ) {
			$rows[] = array(
				'ip'   => '198.51.100.10',
				'path' => '/a',
				'time' => $time,
			);
		}
		$next = $log->append(
			$rows,
			array(
				'ip'   => '198.51.100.11',
				'path' => '/b',
				'time' => LiveTraffic::CAP,
			)
		);
		self::assertCount( LiveTraffic::CAP, $next );
		self::assertSame( 1, $next[0]['time'] );
		self::assertSame( LiveTraffic::CAP, $next[ LiveTraffic::CAP - 1 ]['time'] );
		self::assertFalse(
			$log->shouldStore(
				false,
				array(
					'REMOTE_ADDR' => '203.0.113.8',
					'REQUEST_URI' => '/',
				)
			)
		);
		self::assertFalse( $log->shouldStore( true, array( 'REQUEST_URI' => '/wp-admin/index.php' ) ) );
		self::assertFalse(
			$log->shouldStore(
				true,
				array(
					'AMSEC_CRON'  => '1',
					'REQUEST_URI' => '/',
				)
			)
		);
		self::assertFalse(
			$log->shouldStore(
				true,
				array(
					'AMSEC_CLI'   => '1',
					'REQUEST_URI' => '/',
				)
			)
		);
		self::assertFalse(
			$log->shouldStore(
				true,
				array(
					'AMSEC_REST'  => '1',
					'REQUEST_URI' => '/',
				)
			)
		);
	}
}
