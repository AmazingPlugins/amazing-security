<?php
namespace AmazingPlugins\Security\Tests\Unit\Network;

use AmazingPlugins\Security\Network\NetworkPolicy;
use PHPUnit\Framework\TestCase;
final class NetworkPolicyTest extends TestCase {
	public function test_exact_schema_and_canonical_rules(): void {
		$p = new NetworkPolicy();
		self::assertSame( 'off', $p->read( null )['mode'] );
		$s = array(
			'version'  => 1,
			'mode'     => 'block',
			'cidrs'    => array( '192.0.2.0/24', '2001:db8::/32' ),
			'methods'  => array( 'POST' ),
			'revision' => str_repeat( 'a', 32 ),
		);
		self::assertSame( $s, $p->read( json_encode( $s ) ) );
		foreach ( array( array( 'cidrs' => array( '192.0.2.123/24' ) ), array( 'cidrs' => array( '192.0.2.0/24', '192.0.2.0/24' ) ), array( 'methods' => array( '*', 'POST' ) ), array( 'methods' => array() ), array( 'methods' => array( 'get' ) ), array( 'mode' => 'auto' ), array( 'revision' => 'x' ) ) as $bad ) {
			self::assertNull( $p->read( json_encode( array_replace( $s, $bad ) ) ) );
		}self::assertNull( $p->read( str_repeat( 'x', 16385 ) ) );}
	public function test_method_admin_cli_cron_address_and_mode_boundaries(): void {
		$p = new NetworkPolicy();
		$s = array(
			'version'  => 1,
			'mode'     => 'block',
			'cidrs'    => array( '192.0.2.0/24' ),
			'methods'  => array( 'POST' ),
			'revision' => str_repeat( 'a', 32 ),
		);
		self::assertTrue( $p->matches( $s, '192.0.2.1', 'POST', false, false, false ) );
		self::assertTrue( $p->matches( $s, '::ffff:192.0.2.1', 'post', false, false, false ) );
		foreach ( array( array( '192.0.3.1', 'POST', false, false, false ), array( '192.0.2.1', 'GET', false, false, false ), array( '192.0.2.1', 'POST', true, false, false ), array( '192.0.2.1', 'POST', false, true, false ), array( '192.0.2.1', 'POST', false, false, true ), array( 'bad', 'POST', false, false, false ) ) as $args ) {
			self::assertFalse( $p->matches( $s, ...$args ) );
		}$s['mode'] = 'observe';
		self::assertTrue( $p->matches( $s, '192.0.2.1', 'POST', false, false, false ) );
		$s['mode'] = 'off';
		self::assertFalse( $p->matches( $s, '192.0.2.1', 'POST', false, false, false ) );
		self::assertFalse( $p->matches( null, '192.0.2.1', 'POST', false, false, false ) );}
}
