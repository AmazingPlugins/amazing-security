<?php
namespace AmazingPlugins\Security\Tests\Unit\Network;

use AmazingPlugins\Security\Network\Cidr;
use PHPUnit\Framework\TestCase;
final class CidrTest extends TestCase {
	public function test_ipv4_ipv6_mapped_network_canonicalization(): void {
		foreach ( array(
			'192.0.2.129/24'               => '192.0.2.0/24',
			'192.0.2.1'                    => '192.0.2.1/32',
			'2001:0DB8:ABCD:0001::1234/48' => '2001:db8:abcd::/48',
			'2001:db8::1'                  => '2001:db8::1/128',
			'::ffff:192.0.2.129/120'       => '192.0.2.0/24',
			'::ffff:c000:201'              => '192.0.2.1/32',
			'0.0.0.0/0'                    => '0.0.0.0/0',
			'::/0'                         => '::/0',
		) as $in => $out ) {
			self::assertSame( $out, Cidr::canonical( $in ) );}}
	public function test_prefix_boundaries_and_mapped_clients(): void {
		foreach ( array( array( '192.0.2.0/24', '192.0.2.255', true ), array( '192.0.2.0/24', '192.0.3.0', false ), array( '192.0.2.0/24', '::ffff:192.0.2.123', true ), array( '2001:db8:8000::/33', '2001:db8:ffff::1', true ), array( '2001:db8:8000::/33', '2001:db8:7fff::1', false ), array( '2001:db8::1/128', '2001:db8::2', false ), array( '::/0', '192.0.2.1', false ), array( '0.0.0.0/0', '255.255.255.255', true ) ) as [$net, $ip, $expected] ) {
			self::assertSame( $expected, Cidr::contains( $net, $ip ) );}}
	public function test_ambiguous_invalid_values_are_refused(): void {
		foreach ( array( '', '10.00.0.1', '0x7f000001', '2130706433', '2001:db8::1%eth0', '[::1]', '::ffff:192.0.2.1/80', '192.0.2.1/33', '2001:db8::/129', '192.0.2.1/-1', '192.0.2.1/01', '192.0.2.1/24/1', "192.0.2.1\n", str_repeat( 'a', 130 ) ) as $in ) {
			self::assertNull( Cidr::canonical( $in ), $in );
		}self::assertFalse( Cidr::contains( '192.0.2.0/24', 'bad' ) );}
}
