<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

/** Idle logout decisions. Stored 0 stays off. */
final class IdleLogout {
	public const OPTION = 'amsec_idle_minutes';
	public const META   = 'amsec_last_seen';

	public static function minutes( mixed $stored ): int {
		if ( is_int( $stored ) ) {
			$value = $stored;
		} elseif ( is_string( $stored ) && 1 === preg_match( '/\A\d+\z/', $stored ) ) {
			$value = (int) $stored;
		} else {
			$value = 0;
		}
		return in_array( $value, array( 15, 30, 60 ), true ) ? $value : 0;
	}

	public static function seen( mixed $meta ): ?int {
		if ( is_int( $meta ) && $meta > 0 ) {
			return $meta;
		}
		if ( is_string( $meta ) && 1 === preg_match( '/\A[1-9]\d*\z/', $meta ) ) {
			return (int) $meta;
		}
		return null;
	}

	/**
	 * Off does nothing. A missing timestamp is stamped. A larger gap logs out.
	 */
	public static function decision( int $minutes, ?int $lastSeen, int $now ): string {
		if ( ! in_array( $minutes, array( 15, 30, 60 ), true ) ) {
			return 'off';
		}
		if ( null === $lastSeen || $lastSeen < 1 ) {
			return 'stamp';
		}
		if ( ( $now - $lastSeen ) > ( $minutes * 60 ) ) {
			return 'logout';
		}
		return 'stamp';
	}
}
