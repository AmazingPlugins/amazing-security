<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

/** Path checks for recovery actions. Nothing here changes a file by itself. */
final class Guard {
	/** @param array<int, string> $allowed */
	public static function directoryAllowed( string $candidate, string $contentDir, array $allowed ): bool {
		if ( is_link( $candidate ) || ! is_dir( $candidate ) ) {
			return false;
		}
		$real = realpath( $candidate );
		$root = realpath( $contentDir );
		if ( ! is_string( $real ) || ! is_string( $root ) || ! InstallPath::inside( $real, $root ) ) {
			return false;
		}
		return in_array( $real, $allowed, true );
	}

	public static function repairRelative( string $relative ): bool {
		if ( ! self::plain( $relative ) ) {
			return false;
		}
		return str_starts_with( $relative, 'wp-includes/' ) || str_starts_with( $relative, 'wp-admin/' ) || str_starts_with( $relative, 'wp-content/themes/' );
	}

	public static function deleteRelative( string $relative, string $phrase ): bool {
		return 'DELETE' === $phrase && self::plain( $relative ) && ( str_starts_with( $relative, 'wp-content/uploads/' ) || str_starts_with( $relative, 'wp-content/themes/' ) || str_starts_with( $relative, 'wp-content/plugins/' ) );
	}

	public static function bytesMatch( string $bytes, string $expected ): bool {
		$actual = hash( 'sha256', $bytes );
		return strlen( $expected ) === strlen( $actual ) && hash_equals( $actual, strtolower( $expected ) );
	}

	public static function tableCap( int $count ): bool {
		return $count >= 1 && $count <= 50;
	}

	private static function plain( string $relative ): bool {
		return 1 === preg_match( '/^[a-z0-9_\\.\\/-]+$/', $relative ) && ! str_contains( $relative, '..' );
	}
}
