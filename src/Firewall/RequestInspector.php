<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class RequestInspector {
	public function __construct( private readonly BundledRequestRules $rules = new BundledRequestRules() ) {}

	public function inspect( array $query, bool $authenticated ): array {
		if ( $authenticated ) {
			return array(
				'state' => 'skip',
				'rules' => array(),
			);
		}
		if ( count( $query ) > 50 ) {
			return array(
				'state' => 'partial',
				'rules' => array(),
			);
		}
		$hits    = array();
		$bytes   = 0;
		$partial = false;
		foreach ( $query as $key => $value ) {
			if ( ! is_string( $key ) || strlen( $key ) > 64 ) {
				$partial = true;
				continue;
			}
			if ( in_array( strtolower( $key ), array( 'password', 'passwd', 'token', 'secret', 'authorization', 'auth', 'api_key', '_wpnonce', 'nonce' ), true ) ) {
				continue;
			}
			if ( ! is_scalar( $value ) ) {
				$partial = true;
				continue;
			}
			$value  = (string) $value;
			$bytes += strlen( $value );
			if ( strlen( $value ) > 2048 || $bytes > 8192 ) {
				$partial = true;
				continue;
			}
			$hits = array_merge( $hits, $this->rules->match( rawurldecode( $value ) ) );
		}
		$hits = array_values( array_unique( $hits ) );
		return array(
			'state' => $partial ? 'partial' : ( array() === $hits ? 'pass' : 'observe' ),
			'rules' => $hits,
		);
	}
}
