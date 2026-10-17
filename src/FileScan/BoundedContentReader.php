<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\FileScan;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class BoundedContentReader {
	public function read( string $root, string $relativePath, IntegrityBudget $budget ): ContentReadResult {
		if ( ! WordPressOrgManifestProvider::safePath( $relativePath ) || is_link( $root ) ) {
			return new ContentReadResult( 'unsafe' );
		}
		$rootPath = realpath( $root );
		if ( false === $rootPath || ! is_dir( $rootPath ) ) {
			return new ContentReadResult( 'unavailable' );
		}
		$parts   = explode( '/', $relativePath );
		$current = $rootPath;
		foreach ( $parts as $part ) {
			$current .= '/' . $part;
			if ( is_link( $current ) ) {
				return new ContentReadResult( 'unsafe' );
			}
		}
		$resolved = realpath( $current );
		if ( false === $resolved ) {
			return new ContentReadResult( 'unavailable' );
		}
		if ( ! str_starts_with( $resolved, $rootPath . DIRECTORY_SEPARATOR ) ) {
			return new ContentReadResult( 'unsafe' );
		}
		$before = lstat( $current );
		if ( false === $before || 0100000 !== ( $before['mode'] & 0170000 ) ) {
			return new ContentReadResult( 'unsafe' );
		}
		$size = (int) $before['size'];
		if ( $size > 2097152 ) {
			return new ContentReadResult( 'oversized' );
		}
		if ( $size > $budget->remainingBytes() || ! $budget->beginFile() ) {
			return new ContentReadResult( 'budget' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.PHP.NoSilencedErrors.Discouraged -- Races can make a checked file unreadable; report unavailable.
		$handle = @fopen( $current, 'rb' );
		if ( false === $handle ) {
			return new ContentReadResult( 'unavailable' );
		}
		try {
			$opened = fstat( $handle );
			if ( false === $opened || $opened['dev'] !== $before['dev'] || $opened['ino'] !== $before['ino'] || $opened['size'] !== $before['size'] ) {
				return new ContentReadResult( 'unsafe' );
			}
			$bytes = '';
			while ( ! feof( $handle ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded streaming read of a local file.
				$chunk = fread( $handle, 65536 );
				if ( false === $chunk ) {
					return new ContentReadResult( 'unavailable' );
				}
				if ( strlen( $bytes ) + strlen( $chunk ) > 2097152 || ! $budget->addBytes( strlen( $chunk ) ) ) {
					return new ContentReadResult( 'budget' );
				}
				$bytes .= $chunk;
			}
			$after = lstat( $current );
			if ( false === $after || is_link( $current ) || $after['dev'] !== $opened['dev'] || $after['ino'] !== $opened['ino'] || $after['size'] !== $opened['size'] || $after['mtime'] !== $opened['mtime'] || realpath( $current ) !== $resolved ) {
				return new ContentReadResult( 'unsafe' );
			}
			return new ContentReadResult( 'ok', $bytes, hash( 'sha256', $bytes ), strlen( $bytes ) );
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the local read-only file handle.
			fclose( $handle );
		}
	}
}
