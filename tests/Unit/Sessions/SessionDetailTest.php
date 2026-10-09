<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Sessions;

use AmazingPlugins\Security\Sessions\SessionDetail;
use PHPUnit\Framework\TestCase;

final class SessionDetailTest extends TestCase {
	public function test_chrome_on_a_mac_is_named(): void {
		$agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
		self::assertSame( 'Chrome', SessionDetail::browser( $agent ) );
		self::assertSame( 'Mac', SessionDetail::computer( $agent ) );
	}

	public function test_edge_is_not_called_chrome(): void {
		$agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
		self::assertSame( 'Edge', SessionDetail::browser( $agent ) );
		self::assertSame( 'Windows', SessionDetail::computer( $agent ) );
	}

	public function test_an_iphone_is_named(): void {
		$agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1';
		self::assertSame( 'Safari', SessionDetail::browser( $agent ) );
		self::assertSame( 'iPhone', SessionDetail::computer( $agent ) );
	}

	public function test_curl_is_a_command_line_session(): void {
		self::assertSame( 'curl', SessionDetail::browser( 'curl/8.7.1' ) );
		self::assertSame( 'Command line', SessionDetail::computer( 'curl/8.7.1' ) );
	}

	public function test_the_icon_matches_the_computer(): void {
		self::assertSame( 'dashicons-smartphone', SessionDetail::icon( 'iPhone' ) );
		self::assertSame( 'dashicons-tablet', SessionDetail::icon( 'iPad' ) );
		self::assertSame( 'dashicons-editor-code', SessionDetail::icon( 'Command line' ) );
		self::assertSame( 'dashicons-desktop', SessionDetail::icon( 'Mac' ) );
	}

	public function test_location_uses_the_address_wordpress_stored(): void {
		self::assertSame( 'This computer', SessionDetail::place( '127.0.0.1' ) );
		self::assertSame( 'This network', SessionDetail::place( '192.168.1.20' ) );
		self::assertSame( '203.0.113.10', SessionDetail::place( '203.0.113.10' ) );
		self::assertSame( '', SessionDetail::place( 'secret-ip' ) );
	}
}
