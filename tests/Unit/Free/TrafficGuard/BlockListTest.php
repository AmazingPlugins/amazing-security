<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\BlockList;
use PHPUnit\Framework\TestCase;

final class BlockListTest extends TestCase {
	public function test_empty_lists_do_not_block(): void {
		$list   = new BlockList();
		$server = array(
			'HTTP_HOST'       => 'blocked.example',
			'HTTP_USER_AGENT' => 'BadBot',
			'HTTP_REFERER'    => 'https://evil.example/in',
		);
		self::assertFalse( $list->blocked( '', '', '', $server, false ) );
		self::assertFalse( $list->blocked( "\n\n", " \n", "\r\n", $server, false ) );
	}

	public function test_exact_host_blocks(): void {
		$list   = new BlockList();
		$server = array(
			'HTTP_HOST'       => 'blocked.example',
			'HTTP_USER_AGENT' => 'Browser',
			'HTTP_REFERER'    => '',
		);
		self::assertTrue( $list->blocked( "other.example\nblocked.example", '', '', $server, false ) );
		self::assertTrue( $list->blocked( 'Blocked.Example', '', '', $server, false ) );
		self::assertTrue( $list->blocked( 'blocked.example', '', '', array( 'HTTP_HOST' => 'blocked.example:8443' ), false ) );
		self::assertFalse( $list->blocked( 'notblocked.example', '', '', $server, false ) );
		self::assertFalse( $list->blocked( 'blocked.example.evil', '', '', $server, false ) );
	}

	public function test_admin_capability_short_circuits(): void {
		$list   = new BlockList();
		$server = array(
			'HTTP_HOST'       => 'blocked.example',
			'HTTP_USER_AGENT' => 'BadBot',
			'HTTP_REFERER'    => 'https://evil.example/in',
		);
		self::assertFalse( $list->blocked( 'blocked.example', 'BadBot', 'https://evil.example', $server, true ) );
		self::assertTrue( $list->blocked( 'blocked.example', '', '', $server, false ) );
	}

	public function test_twenty_first_block_entry_is_rejected(): void {
		$list  = new BlockList();
		$lines = array();
		for ( $index = 1; $index <= 21; $index++ ) {
			$lines[] = 'host' . $index . '.example';
		}
		$rejected = $list->prepare( implode( "\n", $lines ), 'host', 'admin.example' );
		self::assertFalse( $rejected['ok'] );
		self::assertSame( 'count', $rejected['error'] );

		$accepted = $list->prepare( implode( "\n", array_slice( $lines, 0, 20 ) ) . "\n\n", 'host', 'admin.example' );
		self::assertTrue( $accepted['ok'] );
		self::assertCount( BlockList::MAX_ENTRIES, $list->lines( $accepted['value'] ) );

		$locked = $list->prepare( "admin.example\n", 'host', 'admin.example' );
		self::assertFalse( $locked['ok'] );
		self::assertSame( 'self', $locked['error'] );
	}
}
