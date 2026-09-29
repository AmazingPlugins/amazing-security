<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

final class BundledRequestRules {
	public function version(): string {
		return '2026.09.29.1';
	}

	public function match( string $value ): array {
		$rules = array();
		if ( str_contains( $value, '../' ) || str_contains( $value, '..\\' ) ) {
			$rules[] = 'AS-REST-001';
		}
		if ( preg_match( '/\bunion\s+(?:all\s+)?select\b/i', $value ) ) {
			$rules[] = 'AS-REST-002';
		}
		return $rules;
	}
}
