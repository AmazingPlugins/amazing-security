<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

final class Cidr {
	private static function address( string $ip ): ?array {
		if ( strlen( $ip ) > 45 || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}$bytes = inet_pton( $ip );
		if ( false === $bytes ) {
			return null;
		}$mapped = strlen( $bytes ) === 16 && substr( $bytes, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff";
		return array(
			'bytes'  => $mapped ? substr( $bytes, 12 ) : $bytes,
			'mapped' => $mapped,
		);
	}
	private static function network( string $raw ): ?array {
		if ( strlen( $raw ) > 64 || preg_match( '/[\x00-\x20\x7F]/', $raw ) ) {
			return null;
		}$parts = explode( '/', $raw );
		if ( count( $parts ) > 2 ) {
			return null;
		}$a = self::address( $parts[0] );
		if ( null === $a ) {
			return null;
		}$width = $a['mapped'] ? 128 : strlen( $a['bytes'] ) * 8;
		$bits   = $width;
		if ( isset( $parts[1] ) ) {
			if ( ! preg_match( '/^(?:0|[1-9][0-9]{0,2})$/D', $parts[1] ) ) {
				return null;
			}$bits = (int) $parts[1];
		}if ( $bits > $width || ( $a['mapped'] && $bits < 96 ) ) {
			return null;
		}if ( $a['mapped'] ) {
			$bits -= 96;
		}return array(
			'bytes' => self::mask( $a['bytes'], $bits ),
			'bits'  => $bits,
		);
	}
	private static function mask( string $bytes, int $bits ): string {
		$out    = '';
		$length = strlen( $bytes ); for ( $i = 0;$i < $length;$i++ ) {
			$left = max( 0, min( 8, $bits - $i * 8 ) );
			$out .= chr( ord( $bytes[ $i ] ) & ( 0 === $left ? 0 : ( 0xff << ( 8 - $left ) ) & 0xff ) );
		}return $out;}
	public static function canonical( string $raw ): ?string {
		$n = self::network( $raw );
		return null === $n ? null : inet_ntop( $n['bytes'] ) . '/' . $n['bits'];}
	public static function contains( string $network, string $address ): bool {
		$n = self::network( $network );
		$a = self::address( $address );
		return null !== $n && null !== $a && strlen( $n['bytes'] ) === strlen( $a['bytes'] ) && self::mask( $a['bytes'], $n['bits'] ) === $n['bytes'];}
	public static function validAddress( string $address ): bool {
		return null !== self::address( $address );}
}
