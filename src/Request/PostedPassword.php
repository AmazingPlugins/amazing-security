<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Request;

defined( 'ABSPATH' ) || exit;

/**
 * Reads a posted password. Sanitizing would change what the user typed, so the value is validated instead:
 * it must be a string, valid UTF-8, free of control characters and within the length limit.
 */
final class PostedPassword {
	public const MAX_BYTES = 1024;

	/** Returns the password exactly as typed, or null when the field is missing or not acceptable. */
	public static function read( string $key, int $max = self::MAX_BYTES ): ?string {
		// Callers verify their own nonce or run inside a core form that already did.
		if ( ! isset( $_POST[ $key ] ) || ! is_string( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return null;
		}
		$raw   = wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Validated below, never altered.
		$value = wp_check_invalid_utf8( $raw ); // Returns '' for invalid UTF-8.
		if ( $value !== $raw ) {
			return null;
		}
		return self::valid( $value, $max ) ? $value : null;
	}

	/** True when the field was sent but cannot be accepted, so a policy check must not silently skip it. */
	public static function rejected( string $key, int $max = self::MAX_BYTES ): bool {
		return isset( $_POST[ $key ] ) && '' !== $_POST[ $key ] && null === self::read( $key, $max ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Presence check only; the value is never used.
	}

	public static function valid( string $value, int $max = self::MAX_BYTES ): bool {
		return strlen( $value ) <= $max && 1 !== preg_match( '/[\x00-\x1F\x7F]/', $value );
	}
}
