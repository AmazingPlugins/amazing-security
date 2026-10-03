<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class BundledRequestRules {
	public function version(): string {
		return '2026.10.03.3';
	}

	public function ids(): array {
		return array( 'AS-REST-001', 'AS-REST-002', 'AS-REST-003', 'AS-REST-004', 'AS-REST-005', 'AS-REST-006' );
	}

	public function match( string $value ): array {
		$rules = array();
		if ( str_contains( $value, '../' ) || str_contains( $value, '..\\' ) ) {
			$rules[] = 'AS-REST-001';
		}
		if ( preg_match( '/\bunion\s+(?:all\s+)?select\b/i', $value ) ) {
			$rules[] = 'AS-REST-002';
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
