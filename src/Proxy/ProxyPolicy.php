<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Proxy;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Network\Cidr;
final class ProxyPolicy {
	public function read( mixed $raw ): ?array {
		if ( null === $raw ) {
			return array(
				'version'  => 1,
				'mode'     => 'off',
				'cidrs'    => array(),
				'revision' => str_repeat( '0', 32 ),
			); }
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure exact bounded local policy.
		$s = is_string( $raw ) && strlen( $raw ) <= 16384 ? json_decode( $raw, true ) : null;
		if ( ! is_array( $s ) || array_keys( $s ) !== array( 'version', 'mode', 'cidrs', 'revision' ) || 1 !== $s['version'] || ! in_array( $s['mode'], array( 'off', 'xff', 'single' ), true ) || ! is_array( $s['cidrs'] ) || ! array_is_list( $s['cidrs'] ) || count( $s['cidrs'] ) > 50 || ( 'off' !== $s['mode'] && array() === $s['cidrs'] ) || ! is_string( $s['revision'] ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $s['revision'] ) ) {
			return null; }
		foreach ( $s['cidrs'] as $cidr ) {
			if ( ! is_string( $cidr ) || Cidr::canonical( $cidr ) !== $cidr || str_ends_with( $cidr, '/0' ) ) {
					return null; }
		}
		return count( array_unique( $s['cidrs'] ) ) === count( $s['cidrs'] ) ? $s : null;
	}
	public function fingerprint( mixed $raw ): string {
		return hash( 'sha256', is_string( $raw ) ? $raw : 'amsec-proxy-missing' ); }
}
