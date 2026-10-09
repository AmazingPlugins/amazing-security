<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class BundledRequestRules {
	public function version(): string {
		return '2026.10.07.3';
	}

	public function ids(): array {
		return array( 'AS-REST-001', 'AS-REST-002', 'AS-REST-003', 'AS-REST-004', 'AS-REST-005', 'AS-REST-006' );
	}

	public function match( string $value ): array {
		$rules = array();
		if ( 1 === preg_match( '#\.\./[A-Za-z0-9._~-]#', $value ) || 1 === preg_match( '#\.\.\\\\[A-Za-z0-9._~-]#', $value ) ) {
			$rules[] = 'AS-REST-001';
		}
		if ( 1 === preg_match( '/\bunion\s+(?:all\s+)?select\b/i', $value, $match, PREG_OFFSET_CAPTURE ) ) {
			$around = trim( substr( $value, 0, $match[0][1] ) . ' ' . substr( $value, $match[0][1] + strlen( $match[0][0] ) ) );
			$words  = preg_split( '/\s+/', $around, -1, PREG_SPLIT_NO_EMPTY );
			$plain  = 0;
			if ( is_array( $words ) ) {
				foreach ( $words as $word ) {
					if ( 1 === preg_match( '/^[A-Za-z][A-Za-z\'-]{2,}$/', $word ) ) {
						++$plain;
					}
				}
			}
			if ( $plain < 2 ) {
				$rules[] = 'AS-REST-002';
			}
		}
		if ( preg_match( '/<script\b|javascript\s*:/i', $value ) ) {
			$rules[] = 'AS-REST-003';
		}
		if ( preg_match( '/\b(?:php|phar|expect):\/\//i', $value ) ) {
			$rules[] = 'AS-REST-004';
		}
		if ( str_contains( $value, "\0" ) ) {
			$rules[] = 'AS-REST-005';
		}
		if ( preg_match( '/\bon(?:error|load)\s*=/i', $value ) ) {
			$rules[] = 'AS-REST-006';
		}
		return $rules;
	}
}
