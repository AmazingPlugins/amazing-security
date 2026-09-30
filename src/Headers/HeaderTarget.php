<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

final class HeaderTarget {
	public static function url( string $raw ): ?string {
		if ( strlen( $raw ) > 512 || preg_match( '/[^\x21-\x7E]|[\\\\%]/', $raw ) ) {
			return null;}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure fixed URL validation independent of WordPress.
		$p = parse_url( $raw );
		if ( ! is_array( $p ) || ! isset( $p['scheme'], $p['host'] ) || isset( $p['user'] ) || isset( $p['pass'] ) || isset( $p['query'] ) || isset( $p['fragment'] ) || ! in_array( $p['scheme'], array( 'http', 'https' ), true ) ) {
			return null;}
		$host = strtolower( $p['host'] );
		$port = $p['port'] ?? ( 'https' === $p['scheme'] ? 443 : 80 );
		$path = $p['path'] ?? '/';
		if ( ( 'https' === $p['scheme'] ? 443 : 80 ) !== $port || ! preg_match( '#^/[a-zA-Z0-9/_.~-]*$#D', $path ) || preg_match( '~(?:^|/)\.{1,2}(?:/|$)~', $path ) ) {
			return null;}
		if ( filter_var( $host, FILTER_VALIDATE_IP ) !== false ) {
			if ( ! self::publicIp( $host ) ) {
				return null;
			}
		} elseif ( strlen( $host ) > 253 || ! preg_match( '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D', $host ) ) {
			return null;}
		return $p['scheme'] . '://' . $host . $path;
	}
	public static function publicIp( string $ip ): bool {
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;}
		$n = unpack( 'N', inet_pton( $ip ) )[1];
		foreach ( array( array( '0.0.0.0', 8 ), array( '100.64.0.0', 10 ), array( '192.0.0.0', 24 ), array( '192.0.2.0', 24 ), array( '192.88.99.0', 24 ), array( '198.18.0.0', 15 ), array( '198.51.100.0', 24 ), array( '203.0.113.0', 24 ), array( '224.0.0.0', 3 ) ) as [$base, $bits] ) {
			$mask = ( 0xffffffff << ( 32 - $bits ) ) & 0xffffffff;
			if ( ( $n & $mask ) === ( unpack( 'N', inet_pton( $base ) )[1] & $mask ) ) {
				return false;}
		}
		return true;
	}
}
