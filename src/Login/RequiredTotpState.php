<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class RequiredTotpState {
	public static function evaluate( mixed $record, string $generation, int $now ): string {
		if ( '' === $record ) {
			return 'new';
		}
		if ( ! is_array( $record ) || ! is_string( $record['generation'] ?? null ) || ! preg_match( '/^[a-f0-9]{32}$/D', $record['generation'] ) || ! is_int( $record['deadline'] ?? null ) || $record['deadline'] < 1 ) {
			return 'unavailable';
		}
		if ( ! hash_equals( $generation, $record['generation'] ) ) {
			return 'new';
		}
		return $now < $record['deadline'] ? 'grace' : 'expired';
	}
}
