<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\LoginNotice;

/** Send or skip an administrator sign-in email. No WordPress calls. */
final class Decision {
	public const OPTION = 'amsec_login_email';
	public const META   = 'amsec_login_email_sent';
	public const GAP    = 3600;

	public static function flag( mixed $value ): string {
		return '1' === $value ? '1' : '0';
	}

	public static function lastSent( mixed $stored ): ?int {
		if ( is_int( $stored ) && $stored > 0 ) {
			return $stored;
		}
		if ( is_string( $stored ) && 1 === preg_match( '/\A[1-9]\d*\z/', $stored ) ) {
			return (int) $stored;
		}
		return null;
	}

	/**
	 * Option "1" and manage_options are required. A missing last send sends once.
	 * A gap under 3600 seconds skips.
	 */
	public static function decide( string $option, bool $canManageOptions, ?int $lastSent, int $now ): string {
		if ( '1' !== $option || ! $canManageOptions ) {
			return 'skip';
		}
		if ( null === $lastSent || $lastSent < 1 ) {
			return 'send';
		}
		if ( ( $now - $lastSent ) < self::GAP ) {
			return 'skip';
		}
		return 'send';
	}

	public static function body( string $siteName, int $now ): string {
		return $siteName . "\n" . gmdate( 'Y-m-d H:i:s', $now ) . ' UTC';
	}
}
