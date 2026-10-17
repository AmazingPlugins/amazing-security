<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

defined( 'ABSPATH' ) || exit;

final class TrafficPolicy {
	public function read( mixed $raw ): ?array {
		if ( null === $raw ) {
			return array(
				'version'  => 1,
				'enabled'  => false,
				'revision' => str_repeat( '0', 32 ),
			); }
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded exact local policy.
		$s = is_string( $raw ) && strlen( $raw ) <= 2048 ? json_decode( $raw, true ) : null;
		return is_array( $s ) && array_keys( $s ) === array( 'version', 'enabled', 'revision' ) && 1 === $s['version'] && is_bool( $s['enabled'] ) && is_string( $s['revision'] ) && 1 === preg_match( '/^[a-f0-9]{32}$/D', $s['revision'] ) ? $s : null;
	}
	public function fingerprint( mixed $raw ): string {
		return hash( 'sha256', is_string( $raw ) ? $raw : 'amsec-traffic-missing' ); }
}
