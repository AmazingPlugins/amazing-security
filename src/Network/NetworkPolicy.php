<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

defined( 'ABSPATH' ) || exit;

final class NetworkPolicy {
	public const METHODS = array( 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS' );
	public function read( mixed $raw ): ?array {
		if ( null === $raw ) {
			return array(
				'version'  => 1,
				'mode'     => 'off',
				'cidrs'    => array(),
				'methods'  => array( '*' ),
				'revision' => str_repeat( '0', 32 ),
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Exact bounded local policy schema.
		$s = is_string( $raw ) && strlen( $raw ) <= 16384 ? json_decode( $raw, true ) : null;
		if ( ! is_array( $s ) || array_keys( $s ) !== array( 'version', 'mode', 'cidrs', 'methods', 'revision' ) || 1 !== $s['version'] || ! in_array( $s['mode'], array( 'off', 'observe', 'block' ), true ) || ! is_array( $s['cidrs'] ) || ! array_is_list( $s['cidrs'] ) || count( $s['cidrs'] ) > 50 || ! is_array( $s['methods'] ) || ! array_is_list( $s['methods'] ) || count( $s['methods'] ) < 1 || count( $s['methods'] ) > 7 || ! is_string( $s['revision'] ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $s['revision'] ) ) {
			return null;}
		foreach ( $s['cidrs'] as $cidr ) {
			if ( ! is_string( $cidr ) || Cidr::canonical( $cidr ) !== $cidr ) {
				return null;
			}
		}if ( count( array_unique( $s['cidrs'] ) ) !== count( $s['cidrs'] ) ) {
			return null;}
		if ( array( '*' ) !== $s['methods'] ) {
			foreach ( $s['methods'] as $method ) {
				if ( ! in_array( $method, self::METHODS, true ) ) {
					return null;
				}
			}if ( count( array_unique( $s['methods'] ) ) !== count( $s['methods'] ) ) {
				return null;}
		}
		return $s;
	}
	public function fingerprint( mixed $raw ): string {
		return hash( 'sha256', is_string( $raw ) ? $raw : 'amsec-network-missing' );}
	public function matches( ?array $s, string $address, string $method, bool $administrator, bool $cli, bool $cron ): bool {
		if ( null === $s || 'off' === $s['mode'] || $administrator || $cli || $cron || ! Cidr::validAddress( $address ) || ( array( '*' ) !== $s['methods'] && ! in_array( strtoupper( $method ), $s['methods'], true ) ) ) {
			return false;}
		foreach ( $s['cidrs'] as $cidr ) {
			if ( Cidr::contains( $cidr, $address ) ) {
				return true;
			}
		}return false;
	}
}
