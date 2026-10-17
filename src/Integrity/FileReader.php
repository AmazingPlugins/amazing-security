<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class FileReader {
	public function hash( string $root, string $relativePath, string $algorithm, IntegrityBudget $budget ): FileHashResult {
		if ( ! WordPressOrgManifestProvider::safePath( $relativePath ) || ! in_array( $algorithm, array( 'md5', 'sha256' ), true ) ) {
			return new FileHashResult( 'unsafe' );
		}
		if ( is_link( $root ) ) {
			return new FileHashResult( 'unsafe' );
		}
		$base = realpath( $root );
		if ( false === $base || ! is_dir( $base ) ) {
			return new FileHashResult( 'unavailable' );
		}
		$path = $base;
		foreach ( explode( '/', $relativePath ) as $part ) {
			$path .= DIRECTORY_SEPARATOR . $part;
			if ( is_link( $path ) ) {
				return new FileHashResult( 'unsafe' );
			}
		}
		if ( ! file_exists( $path ) ) {
			return new FileHashResult( 'missing' );
		}
		$resolved = realpath( $path );
		if ( false === $resolved || ! str_starts_with( $resolved, $base . DIRECTORY_SEPARATOR ) || ! is_file( $resolved ) || ! is_readable( $resolved ) ) {
			return new FileHashResult( 'unsafe' );
		}
		if ( ! $budget->beginFile() ) {
			return new FileHashResult( 'budget' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Bounded stream reads need fopen; a permissions race is inconclusive.
		$stream = @fopen( $resolved, 'rb' );
		if ( false === $stream ) {
			return new FileHashResult( 'unavailable' );
		}
		$hash   = hash_init( $algorithm );
		$sha256 = hash_init( 'sha256' );
		try {
			while ( ! feof( $stream ) ) {
				if ( ! $budget->hasTime() ) {
					return new FileHashResult( 'budget' );
				}
				if ( 0 === $budget->remainingBytes() ) {
					$metadata = fstat( $stream );
					if ( is_array( $metadata ) && isset( $metadata['size'] ) && ftell( $stream ) === $metadata['size'] ) {
						break;
					}
					return new FileHashResult( 'budget' );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Stream chunks enforce the byte budget.
				$chunk = fread( $stream, min( 65536, $budget->remainingBytes() ) );
				if ( false === $chunk ) {
					return new FileHashResult( 'unavailable' );
				}
				if ( '' === $chunk ) {
					break;
				}
				if ( ! $budget->addBytes( strlen( $chunk ) ) ) {
					return new FileHashResult( 'budget' );
				}
				hash_update( $hash, $chunk );
				hash_update( $sha256, $chunk );
			}
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the bounded stream.
			fclose( $stream );
		}
		return new FileHashResult( 'ok', hash_final( $hash ), hash_final( $sha256 ) );
	}
}
