<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\Decisions;
use PHPUnit\Framework\TestCase;

final class DecisionsTest extends TestCase {
	public function test_empty_lists_do_not_block(): void {
		self::assertFalse( Decisions::blocked( array(), array(), array(), 'evil.test', 'BadBot', 'https://evil.test/', false ) );
	}

	public function test_exact_host_blocks_and_an_administrator_does_not(): void {
		self::assertTrue( Decisions::blocked( array( 'evil.test' ), array(), array(), 'evil.test', '', '', false ) );
		self::assertFalse( Decisions::blocked( array( 'evil.test' ), array(), array(), 'evil.test', '', '', true ) );
	}

	public function test_path_drops_the_query_string(): void {
		self::assertSame( '/posts/1', Decisions::path( '/posts/1?password=secret' ) );
	}

	public function test_hotlink_allows_empty_and_same_host(): void {
		self::assertSame( 'allow', Decisions::hotlink( '', 'example.test', '/uploads/a.jpg' ) );
		self::assertSame( 'allow', Decisions::hotlink( 'https://example.test/page', 'example.test', '/uploads/a.jpg' ) );
		self::assertSame( 'block', Decisions::hotlink( 'https://other.test/page', 'example.test', '/uploads/a.jpg' ) );
		self::assertSame( 'skip', Decisions::hotlink( 'https://other.test/page', 'example.test', '/uploads/a.txt' ) );
	}

	public function test_a_twenty_first_entry_is_rejected(): void {
		$lines = array();
		for ( $i = 0; $i < 21; $i++ ) {
			$lines[] = 'host' . $i . '.test';
		}
		$raw = implode( "\n", $lines );
		self::assertTrue( Decisions::tooMany( $raw ) );
		self::assertCount( 20, Decisions::entries( $raw ) );
	}
}
