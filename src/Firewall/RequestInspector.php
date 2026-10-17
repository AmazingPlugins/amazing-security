<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

defined( 'ABSPATH' ) || exit;

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
		$seen    = 0;
		foreach ( $query as $key => $value ) {
			$hits = array_merge( $hits, $this->read( $key, $value, $bytes, $partial, $seen, 5 ) );
		}
		$hits = array_values( array_unique( $hits ) );
		return array(
			'state' => $partial ? 'partial' : ( array() === $hits ? 'pass' : 'observe' ),
			'rules' => $hits,
		);
	}

	private function read( mixed $key, mixed $value, int &$bytes, bool &$partial, int &$seen, int $depth ): array {
		if ( $seen >= 50 ) {
			$partial = true;
			return array();
		}
		++$seen;
		if ( is_int( $key ) ) {
			$key = (string) $key;
		}
		if ( ! is_string( $key ) || strlen( $key ) > 64 ) {
			$partial = true;
			return array();
		}
		if ( in_array( strtolower( $key ), array( 'password', 'passwd', 'token', 'secret', 'authorization', 'auth', 'api_key', '_wpnonce', 'nonce' ), true ) ) {
			return array();
		}
		if ( is_array( $value ) ) {
			if ( $depth < 1 ) {
				$partial = true;
				return array();
			}
			$hits = array();
			foreach ( $value as $childKey => $child ) {
				$hits = array_merge( $hits, $this->read( $childKey, $child, $bytes, $partial, $seen, $depth - 1 ) );
			}
			return $hits;
		}
		if ( ! is_scalar( $value ) ) {
			$partial = true;
			return array();
		}
		$value  = (string) $value;
		$bytes += strlen( $value );
		if ( strlen( $value ) > 2048 || $bytes > 8192 ) {
			$partial = true;
			return array();
		}
		$hits = array();
		foreach ( $this->forms( $value ) as $form ) {
			$hits = array_merge( $hits, $this->rules->match( $form ) );
		}
		return $hits;
	}

	private function forms( string $value ): array {
		$forms   = array();
		$current = $value;
		for ( $step = 0; $step < 6; ++$step ) {
			$next    = rawurldecode( $current );
			$forms[] = $next;
			if ( $next === $current || 1 !== preg_match( '/%[0-9A-Fa-f]{2}/', $next ) ) {
				break;
			}
			$current = $next;
		}
		return $forms;
	}
}
