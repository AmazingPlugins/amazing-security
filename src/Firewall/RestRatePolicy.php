<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

final class RestRatePolicy {
	public const IDS = array( 'users-read', 'comments-create' );
	public function read( mixed $raw ): ?array {
		if ( null === $raw ) {
			return array(
				'version'    => 1,
				'mode'       => 'off',
				'exemptions' => array(),
				'revision'   => str_repeat( '0', 32 ),
			);}
	 // phpcs:ignore WordPress.WP.AlternativeFunctions.json_decode_json_decode -- Pure bounded exact policy schema.
		$s = is_string( $raw ) && strlen( $raw ) <= 4096 ? json_decode( $raw, true ) : null;
		if ( ! is_array( $s ) || array_keys( $s ) !== array( 'version', 'mode', 'exemptions', 'revision' ) || 1 !== $s['version'] || ! in_array( $s['mode'], array( 'off', 'observe', 'block' ), true ) || ! is_array( $s['exemptions'] ) || ! array_is_list( $s['exemptions'] ) || count( $s['exemptions'] ) > 2 || count( array_unique( $s['exemptions'], SORT_REGULAR ) ) !== count( $s['exemptions'] ) || ! is_string( $s['revision'] ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $s['revision'] ) ) {
			return null;}
		foreach ( $s['exemptions'] as $id ) {
			if ( ! in_array( $id, self::IDS, true ) ) {
				return null;
			}
		}return $s;
	}
	public function fingerprint( mixed $raw ): string {
		return hash( 'sha256', is_string( $raw ) ? $raw : 'amsec-rest-rate-missing' );}
	public function target( string $route, string $method, bool $authenticated, mixed $prior ): ?string {
		if ( $authenticated || null !== $prior ) {
			return null;}
		if ( 'GET' === $method && preg_match( '~^/wp/v2/users(?:/[0-9]+)?/?$~i', $route ) ) {
			return 'users-read';}
		return 'POST' === $method && 1 === preg_match( '~^/wp/v2/comments/?$~i', $route ) ? 'comments-create' : null;
	}
	public function reject( string $mode, string $id, array $exemptions, ?int $count ): bool {
		return 'block' === $mode && in_array( $id, self::IDS, true ) && ! in_array( $id, $exemptions, true ) && null !== $count && $count > ( 'users-read' === $id ? 60 : 20 );}
}
