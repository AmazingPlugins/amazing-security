<?php
namespace AmazingPlugins\Security\Tests\Unit\Proxy;

use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Login\AddressKey;
use AmazingPlugins\Security\Proxy\{ProxyNamespace, ProxyResolver};
final class ProxyAddressKeyTest extends TestCase {
	public function testInjectedResolutionUsesClientRatherThanProxyAndUnknownFailsOpen(): void {
		$p       = array(
			'version'  => 1,
			'mode'     => 'xff',
			'cidrs'    => array( '10.0.0.0/8' ),
			'revision' => str_repeat( 'a', 32 ),
		);
		$resolve = static fn( array $server )=>( new ProxyResolver() )->resolve( $p, $server, true );
		$key     = new AddressKey( 'salt', $resolve );
		self::assertSame(
			( new AddressKey( 'salt' ) )->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) ),
			$key->fromServer(
				array(
					'REMOTE_ADDR'          => '10.0.0.1',
					'HTTP_X_FORWARDED_FOR' => '192.0.2.4',
				)
			)
		);
		self::assertNull( $key->fromServer( array( 'REMOTE_ADDR' => '10.0.0.1' ) ) );
		self::assertNull(
			( new AddressKey(
				'salt',
				static function () {
					throw new \RuntimeException( 'failed' );
				}
			) )->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) )
		);
	}
	public function testChangedProxyInterpretationGetsSeparateOpaqueNamespace(): void {
		$s = array(
			'version'  => 1,
			'mode'     => 'xff',
			'cidrs'    => array( '10.0.0.0/8' ),
			'revision' => str_repeat( 'a', 32 ),
		);
		$a = ProxyNamespace::salt( 'salt', $s );
		$b = ProxyNamespace::salt( 'salt', array_replace( $s, array( 'revision' => str_repeat( 'b', 32 ) ) ) );
		self::assertNotSame( $a, $b );
		self::assertSame(
			'salt',
			ProxyNamespace::salt(
				'salt',
				array_replace(
					$s,
					array(
						'mode'     => 'off',
						'revision' => str_repeat( '0', 32 ),
					)
				)
			)
		);
		self::assertNotSame( 'salt', ProxyNamespace::salt( 'salt', array_replace( $s, array( 'mode' => 'off' ) ) ) );
		$server = array( 'REMOTE_ADDR' => '192.0.2.4' );
		self::assertNotSame( ( new AddressKey( $a ) )->fromServer( $server ), ( new AddressKey( $b ) )->fromServer( $server ) );
	}

	public function test_prefix64_groups_ipv6_only(): void {
		$grouped = new \AmazingPlugins\Security\Login\AddressKey( 'salt', null, true );
		$plain   = new \AmazingPlugins\Security\Login\AddressKey( 'salt' );
		self::assertSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2:ffff::9' ) ) );
		self::assertNotSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:3::1' ) ) );
		self::assertNotSame( $plain->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::1' ) ), $plain->fromServer( array( 'REMOTE_ADDR' => '2001:db8:1:2::2' ) ) );
		self::assertSame( $plain->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '192.0.2.4' ) ) );
	}


	public function test_ipv4_inside_ipv6_keeps_its_own_address_under_prefix64(): void {
		$grouped = new AddressKey( 'salt', null, true );
		self::assertSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '203.0.113.5' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '::ffff:203.0.113.5' ) ) );
		self::assertNotSame( $grouped->fromServer( array( 'REMOTE_ADDR' => '::ffff:203.0.113.5' ) ), $grouped->fromServer( array( 'REMOTE_ADDR' => '::ffff:203.0.113.6' ) ) );
	}
}
