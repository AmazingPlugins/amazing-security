<?php
namespace AmazingPlugins\Security\Tests\Unit\Bots;

use AmazingPlugins\Security\Bots\RatePolicy;
use PHPUnit\Framework\TestCase;

final class RatePolicyTest extends TestCase {
	private static function input( array $over = array() ): array {
		return $over + array(
			'mode'  => 'block',
			'page'  => '120',
			'rest'  => '60',
			'login' => '20',
			'block' => '10',
			'allow' => '',
		);
	}

	private static function kind( string $path, string $method = 'GET', string $pagenow = 'index.php', bool $restRoute = false, bool $xmlrpc = false, bool $ajax = false ): string {
		return RatePolicy::classify( $path, $restRoute, '/wp-json/', $pagenow, $method, $xmlrpc, $ajax );
	}

	public function test_classifies_requests(): void {
		self::assertSame( 'page', self::kind( '/' ) );
		self::assertSame( 'page', self::kind( '/about/', 'POST' ) );
		self::assertSame( 'rest', self::kind( '/wp-json/wp/v2/posts' ) );
		self::assertSame( 'rest', self::kind( '/', 'GET', 'index.php', true ) );
		self::assertSame( 'page', self::kind( '/wp-jsonx/' ) );
		self::assertSame( 'xmlrpc', self::kind( '/xmlrpc.php', 'POST', 'xmlrpc.php' ) );
		self::assertSame( 'xmlrpc', self::kind( '/x', 'POST', 'index.php', false, true ) );
		self::assertSame( 'login', self::kind( '/wp-login.php', 'POST', 'wp-login.php' ) );
		self::assertSame( 'page', self::kind( '/wp-login.php', 'GET', 'wp-login.php' ) );
		self::assertSame( 'login', self::kind( '/wp-admin/admin-ajax.php', 'post', 'admin-ajax.php', false, false, true ) );
		self::assertSame( 'page', self::kind( '/wp-admin/admin-ajax.php', 'GET', 'admin-ajax.php', false, false, true ) );
		// The entry script wins over a REST marker, so sign-in posts can't skip their own limit.
		self::assertSame( 'login', self::kind( '/wp-login.php', 'POST', 'wp-login.php', true ) );
		self::assertSame( 'login', self::kind( '/wp-admin/admin-ajax.php', 'POST', 'admin-ajax.php', true, false, true ) );
		self::assertSame( 'page', self::kind( '/wp-login.php', 'GET', 'wp-login.php', true ) );
	}

	public function test_limits_map_xmlrpc_to_rest(): void {
		$s = RatePolicy::defaults();
		self::assertSame( 60, RatePolicy::limit( $s, 'xmlrpc' ) );
		self::assertSame( 120, RatePolicy::limit( $s, 'page' ) );
		self::assertSame( 20, RatePolicy::limit( $s, 'login' ) );
	}

	public function test_valid_input_saves_and_canonicalises(): void {
		list( $s, $e ) = RatePolicy::validate(
			self::input(
				array(
					'page'  => '30',
					'block' => '60',
					'allow' => " 203.0.113.7 \n\n198.51.100.9/24\r\n2001:db8::1\n2001:DB8::/32\n203.0.113.7",
				)
			)
		);
		self::assertSame( array(), $e );
		self::assertSame( 30, $s['page'] );
		self::assertSame( 60, $s['block'] );
		self::assertSame( array( '203.0.113.7', '198.51.100.0/24', '2001:db8::1', '2001:db8::/32' ), $s['allow'] );
	}

	public function test_bounds_are_enforced(): void {
		foreach ( array( array( 'page', '29' ), array( 'page', '601' ), array( 'rest', '9' ), array( 'rest', '301' ), array( 'login', '4' ), array( 'login', '101' ), array( 'block', '0' ), array( 'block', '61' ), array( 'page', '1e3' ), array( 'page', '-50' ), array( 'page', '' ) ) as list( $field, $value ) ) {
			list( $s, $e ) = RatePolicy::validate( self::input( array( $field => $value ) ) );
			self::assertNull( $s, $field . '=' . $value );
			self::assertSame( array( $field ), $e['numbers'] );
		}
		self::assertNull( RatePolicy::validate( self::input( array( 'mode' => 'on' ) ) )[0] );
	}

	public function test_invalid_lines_are_reported_not_dropped(): void {
		list( $s, $e ) = RatePolicy::validate( self::input( array( 'allow' => "203.0.113.7\nexample.com\n\n10.0.0.0/33\n::1/129" ) ) );
		self::assertNull( $s );
		self::assertSame( array( 2, 4, 5 ), $e['lines'] );
		$many = implode( "\n", array_map( static fn( int $i ): string => '10.0.0.' . $i, range( 1, 51 ) ) );
		self::assertTrue( RatePolicy::validate( self::input( array( 'allow' => $many ) ) )[1]['too_many'] );
	}

	public function test_read_falls_back_to_defaults(): void {
		self::assertSame( RatePolicy::defaults(), RatePolicy::read( 'junk' ) );
		$s = RatePolicy::read(
			array(
				'mode'  => 'block',
				'page'  => 5000,
				'rest'  => '60',
				'login' => 50,
				'allow' => array( '10.0.0.0/8', 'bad', 7 ),
			)
		);
		self::assertSame( 'block', $s['mode'] );
		self::assertSame( 120, $s['page'] );
		self::assertSame( 60, $s['rest'] );
		self::assertSame( 50, $s['login'] );
		self::assertSame( array( '10.0.0.0/8' ), $s['allow'] );
		self::assertSame( 'off', RatePolicy::read( array( 'mode' => 'panic' ) )['mode'] );
	}

	public function test_cidr_matching_for_ipv4_and_ipv6(): void {
		$allow = array( '198.51.100.0/24', '203.0.113.7', '2001:db8::/32' );
		self::assertTrue( RatePolicy::listed( '198.51.100.250', $allow ) );
		self::assertTrue( RatePolicy::listed( '203.0.113.7', $allow ) );
		self::assertTrue( RatePolicy::listed( '2001:db8:ffff::1', $allow ) );
		self::assertFalse( RatePolicy::listed( '198.51.101.1', $allow ) );
		self::assertFalse( RatePolicy::listed( '203.0.113.8', $allow ) );
		self::assertFalse( RatePolicy::listed( '2001:db9::1', $allow ) );
		self::assertFalse( RatePolicy::listed( '198.51.100.1', array() ) );
	}

	public function test_server_itself_only_when_no_forwarded_address(): void {
		self::assertTrue( RatePolicy::fromServer( '127.0.0.1', '127.0.0.1', '' ) );
		self::assertTrue( RatePolicy::fromServer( '::1', '::1', '' ) );
		self::assertTrue( RatePolicy::fromServer( '172.17.0.2', '172.17.0.2', '172.17.0.2' ) );
		// A trusted proxy on loopback forwarded a real visitor: count the visitor.
		self::assertFalse( RatePolicy::fromServer( '127.0.0.1', '203.0.113.7', '' ) );
		self::assertFalse( RatePolicy::fromServer( '203.0.113.7', '203.0.113.7', '172.17.0.2' ) );
		self::assertFalse( RatePolicy::fromServer( '', '', '' ) );
	}

	public function test_watch_and_block_decision(): void {
		self::assertSame( 'none', RatePolicy::decide( 'block', 30, 30 ) );
		self::assertSame( 'block', RatePolicy::decide( 'block', 31, 30 ) );
		self::assertSame( 'flag', RatePolicy::decide( 'watch', 31, 30 ) );
		self::assertSame( 'flag', RatePolicy::decide( 'watch', 5000, 30 ) );
		self::assertSame( 'none', RatePolicy::decide( 'off', 5000, 30 ) );
		self::assertSame( 'none', RatePolicy::decide( 'block', null, 30 ) );
	}
}
