<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Files;

/** Replace a small text file without ever leaving it half written. Refuses symlinks and oversized content. */
final class AtomicWrite {
	public const MAX_BYTES = 65536;

	public static function write( string $path, string $contents ): bool {
		$directory = dirname( $path );
		if ( strlen( $contents ) > self::MAX_BYTES || is_link( $path ) || is_link( $directory ) || ! is_dir( $directory ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Confirms the folder accepts a replacement file.
		if ( ! is_writable( $directory ) ) {
			return false;
		}
		$mode = is_file( $path ) ? ( fileperms( $path ) & 0777 ) : 0644;
		$temp = $directory . '/.' . basename( $path ) . '.amsec-' . bin2hex( random_bytes( 6 ) ) . '.tmp';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Write the replacement beside the target, then rename it into place.
		$written = file_put_contents( $temp, $contents, LOCK_EX );
		if ( strlen( $contents ) !== $written ) {
			self::discard( $temp );
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keep the permissions of the file being replaced.
		chmod( $temp, $mode );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Atomic replacement on the same filesystem.
		if ( ! rename( $temp, $path ) ) {
			self::discard( $temp );
			return false;
		}
		return true;
	}

	private static function discard( string $temp ): void {
		if ( is_file( $temp ) ) {
			wp_delete_file( $temp );
		}
	}
}
