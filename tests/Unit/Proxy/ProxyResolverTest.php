<?php
namespace AmazingPlugins\Security\Tests\Unit\Proxy;

use PHPUnit\Framework\TestCase;
use AmazingPlugins\Security\Proxy\{ProxyPolicy, ProxyResolver};
final class ProxyResolverTest extends TestCase {
	private function policy( string $mode = 'xff' ): array {
		return array(
			'version'  => 1,
			'mode'     => $mode,
			'cidrs'    => array( '10.0.0.0/8', '2001:db8:1::/48' ),
			'revision' => str_repeat( 'd', 32 ),
		);}
	public function testDefaultOffIgnoresHeadersButActiveModeRequiresHostConfirmation(): void {
		$r = new ProxyResolver();
		$p = new ProxyPolicy();
		self::assertSame(
			'192.0.2.4',
			$r->resolve(
				$p->read( null ),
				array(
					'REMOTE_ADDR'          => '192.0.2.4',
					'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
				),
				false
			)
		);
		self::assertNull(
			$r->resolve(
				$this->policy(),
				array(
					'REMOTE_ADDR'          => '10.0.0.1',
					'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
				),
				false
			)
		);
		self::assertNull( $r->resolve( null, array( 'REMOTE_ADDR' => '192.0.2.4' ), true ) );
	}
	public function testOnlyTrustedPeerCanSupplyChainAndFirstUntrustedHopIsBoundary(): void {
		$r = new ProxyResolver();
		$p = $this->policy();
		self::assertSame(
			'192.0.2.4',
			$r->resolve(
				$p,
				array(
					'REMOTE_ADDR'          => '192.0.2.4',
					'HTTP_X_FORWARDED_FOR' => '8.8.8.8',
				),
				true
			)
		);
		self::assertSame(
			'192.0.2.4',
			$r->resolve(
				$p,
				array(
					'REMOTE_ADDR'          => '10.0.0.1',
					'HTTP_X_FORWARDED_FOR' => '8.8.8.8, 192.0.2.4, 10.0.0.2',
				),
				true
			)
		);
		self::assertSame(
			'2001:db8:2::1',
			$r->resolve(
				$p,
				array(
					'REMOTE_ADDR'          => '2001:db8:1::1',
					'HTTP_X_FORWARDED_FOR' => '2001:db8:2::1, 2001:db8:1::2',
				),
				true
			)
		);
		self::assertSame(
			'192.0.2.4',
			$r->resolve(
				$p,
				array(
					'REMOTE_ADDR'          => '::ffff:10.0.0.1',
					'HTTP_X_FORWARDED_FOR' => '::ffff:192.0.2.4, 10.0.0.2',
				),
				true
			)
		);
	}
	public function testTrustedPeerMalformedMissingOrAllTrustedChainIsUnknown(): void {
		$r = new ProxyResolver();
		foreach ( array( null, array(), false, '', '10.0.0.2', '192.0.2.4,', 'secret, 192.0.2.4', '192.0.2.4:123', '[2001:db8::1]', 'fe80::1%eth0', "192.0.2.4\n", str_repeat( '1', 2049 ), implode( ',', array_fill( 0, 33, '192.0.2.4' ) ) ) as $header ) {
			$server = array( 'REMOTE_ADDR' => '10.0.0.1' );
			if ( null !== $header ) {
				$server['HTTP_X_FORWARDED_FOR'] = $header;
			}self::assertNull( $r->resolve( $this->policy(), $server, true ) );}
		self::assertNull(
			$r->resolve(
				$this->policy(),
				array(
					'REMOTE_ADDR'          => 'invalid',
					'HTTP_X_FORWARDED_FOR' => '192.0.2.4',
				),
				true
			)
		);
	}
	public function testSingleSelectedHeaderNeverFallsBackToAnotherHeader(): void {
		$r = new ProxyResolver();
		$p = $this->policy( 'single' );
		self::assertSame(
			'192.0.2.4',
			$r->resolve(
				$p,
				array(
					'REMOTE_ADDR'           => '10.0.0.1',
					'HTTP_CF_CONNECTING_IP' => '192.0.2.4',
					'HTTP_X_FORWARDED_FOR'  => '8.8.8.8',
				),
				true
			)
		);
		foreach ( array( '192.0.2.4, 192.0.2.5', 'invalid', '' ) as $v ) {
			self::assertNull(
				$r->resolve(
					$p,
					array(
						'REMOTE_ADDR'           => '10.0.0.1',
						'HTTP_CF_CONNECTING_IP' => $v,
						'HTTP_X_FORWARDED_FOR'  => '8.8.8.8',
					),
					true
				)
			);
		}
	}
	public function testPolicyRejectsGlobalTrustDuplicatesNoncanonicalAndCorruption(): void {
		$p = new ProxyPolicy();
		$s = $this->policy();
		self::assertSame( $s, $p->read( json_encode( $s ) ) );
		foreach ( array( false, 'corrupt', json_encode( $s + array( 'header' => 'arbitrary' ) ), json_encode( array_replace( $s, array( 'cidrs' => array( '0.0.0.0/0' ) ) ) ), json_encode( array_replace( $s, array( 'cidrs' => array( '::/0' ) ) ) ), json_encode( array_replace( $s, array( 'cidrs' => array( '10.0.0.1/8' ) ) ) ), json_encode( array_replace( $s, array( 'cidrs' => array( '10.0.0.0/8', '10.0.0.0/8' ) ) ) ), json_encode( array_replace( $s, array( 'cidrs' => array() ) ) ), json_encode( array_replace( $s, array( 'mode' => 'auto' ) ) ), json_encode( array_replace( $s, array( 'revision' => 'invalid' ) ) ) ) as $raw ) {
			self::assertNull( $p->read( $raw ) );
		}
	}
}
