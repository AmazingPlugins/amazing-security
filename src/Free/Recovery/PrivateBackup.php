<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Writes private copies outside the install. A failed backup does not delete the source. */
final class PrivateBackup {
	private readonly string $siteRoot;
	private readonly string $backupDirectory;

	public function __construct( string $siteRoot, string $backupDirectory ) {
		$this->siteRoot        = self::trim( $siteRoot );
		$this->backupDirectory = self::trim( $backupDirectory );
	}

	public function directory(): ?string {
		$backup = realpath( $this->backupDirectory );
		$site   = realpath( $this->siteRoot );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- The backup directory is outside the install and is checked before a private copy.
		if ( false === $backup || false === $site || ! is_dir( $backup ) || ! is_writable( $backup ) ) {
			return null;
		}
		if ( InstallPath::inside( $backup, $site ) ) {
			return null;
		}
		return $backup;
	}

	public function write( string $bytes ): ?string {
		$directory = $this->directory();
		if ( null === $directory ) {
			return null;
		}
		return $this->writeBytes( $directory, $bytes );
	}

	/**
	 * Move a regular file out of the install. removed is false when the original is still there.
	 *
	 * @return array{removed: bool, backedUp: bool}
	 */
	public function move( string $source ): array {
		$kept      = array(
			'removed'  => false,
			'backedUp' => false,
		);
		$directory = $this->directory();
		if ( null === $directory || is_link( $source ) || ! is_file( $source ) ) {
			return $kept;
		}
		$path = $this->freshPath( $directory );
		if ( null === $path ) {
			return $kept;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Move the unexpected file out of the install before any unlink.
		if ( rename( $source, $path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Private backup is owner-read only.
			chmod( $path, 0600 );
			return array(
				'removed'  => true,
				'backedUp' => true,
			);
		}
		clearstatcache( true, $source );
		if ( is_link( $source ) || ! is_file( $source ) ) {
			return $kept;
		}
		$size = filesize( $source );
		if ( false === $size || $size > DatabaseDump::MAX_BYTES ) {
			return $kept;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read the source only after rename could not move it.
		$bytes = file_get_contents( $source );
		if ( ! is_string( $bytes ) || strlen( $bytes ) !== $size ) {
			return $kept;
		}
		$copied = $this->writeBytes( $directory, $bytes );
		if ( null === $copied ) {
			return $kept;
		}
		clearstatcache( true, $source );
		$sourceHash = is_link( $source ) || ! is_file( $source ) ? false : hash_file( 'sha256', $source );
		$copyHash   = hash_file( 'sha256', $copied );
		if ( ! is_string( $sourceHash ) || ! is_string( $copyHash ) || ! hash_equals( $sourceHash, $copyHash ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop a backup that does not match. The source stays.
			unlink( $copied );
			return $kept;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Unlink only after the private backup hash matches.
		if ( ! unlink( $source ) ) {
			return array(
				'removed'  => false,
				'backedUp' => true,
			);
		}
		return array(
			'removed'  => true,
			'backedUp' => true,
		);
	}

	private function writeBytes( string $directory, string $bytes ): ?string {
		$path = $this->freshPath( $directory );
		if ( null === $path ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Exclusive create for a private backup outside the site.
		$handle = fopen( $path, 'xb' );
		if ( false === $handle ) {
			return null;
		}
		$written = 0;
		$length  = strlen( $bytes );
		while ( $written < $length ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Bounded write to the private backup.
			$part = fwrite( $handle, substr( $bytes, $written ) );
			if ( false === $part || 0 === $part ) {
				break;
			}
			$written += $part;
		}
		$flushed = fflush( $handle );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the private backup stream.
		$closed = fclose( $handle );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Private backup is owner-read only.
		if ( ! $flushed || ! $closed || $written !== $length || ! chmod( $path, 0600 ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop an unfinished private backup.
			unlink( $path );
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Read back the private backup before trusting it.
		$check = file_get_contents( $path );
		if ( ! is_string( $check ) || ! hash_equals( hash( 'sha256', $bytes ), hash( 'sha256', $check ) ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Drop a private backup that does not match.
			unlink( $path );
			return null;
		}
		return $path;
	}

	private function freshPath( string $directory ): ?string {
		try {
			$name = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable ) {
			return null;
		}
		return $directory . '/amsec-' . $name . '.bak';
	}

	private static function trim( string $path ): string {
		$trimmed = rtrim( $path, '/\\' );
		return '' === $trimmed ? $path : $trimmed;
	}
}
