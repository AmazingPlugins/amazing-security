<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use DateTimeImmutable;
use ZipArchive;

final class ThemeArchiveParser {
	/** Reads a release ZIP that WordPress downloaded to its temp directory. The caller deletes it. */
	public function parse( string $slug, string $version, string $archivePath, string $sourceUrl ): ManifestResult {
		if ( ! class_exists( ZipArchive::class ) ) {
			return new ManifestResult( null, 'zip_unavailable' );
		}
		$bytes = is_file( $archivePath ) ? filesize( $archivePath ) : false;
		if ( false === $bytes || 0 === $bytes || $bytes > 16777216 ) {
			return new ManifestResult( null, 'oversized_archive' );
		}
		$zip    = new ZipArchive();
		$opened = false;
		try {
			$opened = true === $zip->open( $archivePath, ZipArchive::RDONLY );
			if ( ! $opened ) {
				return new ManifestResult( null, 'invalid_archive' );
			}
			if ( $zip->numFiles < 1 || $zip->numFiles > 10000 ) {
				return new ManifestResult( null, 'invalid_archive' );
			}
			$entries = array();
			$seen    = array();
			$total   = 0;
			$prefix  = $slug . '/';
			for ( $i = 0; $i < $zip->numFiles; ++$i ) {
				$stat = $zip->statIndex( $i );
				if ( false === $stat || ! isset( $stat['name'], $stat['size'], $stat['comp_size'] ) || ! is_string( $stat['name'] ) ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$name = $stat['name'];
				if ( ! str_starts_with( $name, $prefix ) ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$directory = str_ends_with( $name, '/' );
				$relative  = substr( $name, strlen( $prefix ) );
				$relative  = $directory ? rtrim( $relative, '/' ) : $relative;
				if ( '' !== $relative && ! WordPressOrgManifestProvider::safePath( $relative ) ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				if ( '' === $relative && ! $directory ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$key = strtolower( $relative );
				if ( isset( $seen[ $key ] ) ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$seen[ $key ] = true;
				$zip->getExternalAttributesIndex( $i, $opsys, $attributes );
				if ( isset( $opsys, $attributes ) && ZipArchive::OPSYS_UNIX === $opsys && 0120000 === ( ( $attributes >> 16 ) & 0170000 ) ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$size       = (int) $stat['size'];
				$compressed = (int) $stat['comp_size'];
				$total     += $size;
				if ( $total > 67108864 || $size < 0 || ( $size > 0 && $size > 100 * max( 1, $compressed ) ) ) {
					return new ManifestResult( null, 'oversized_archive' );
				}
				if ( ! $directory ) {
					$entries[ $relative ] = $name;
				}
			}
			if ( array() === $entries ) {
				return new ManifestResult( null, 'invalid_archive' );
			}
			$files = array();
			foreach ( $entries as $relative => $name ) {
				$stream = $zip->getStream( $name );
				if ( false === $stream ) {
					return new ManifestResult( null, 'invalid_archive' );
				}
				$hash = hash_init( 'sha256' );
				$read = 0;
				while ( ! feof( $stream ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Read a validated archive entry stream, not a WordPress file.
					$chunk = fread( $stream, 65536 );
					if ( false === $chunk ) {
						// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the archive entry stream.
						fclose( $stream );
						return new ManifestResult( null, 'invalid_archive' );
					}
					$read += strlen( $chunk );
					hash_update( $hash, $chunk );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close the archive entry stream.
				fclose( $stream );
				if ( $read > 67108864 ) {
					return new ManifestResult( null, 'oversized_archive' );
				}
				$files[ $relative ] = array( hash_final( $hash ) );
			}
			return new ManifestResult( new Manifest( 'theme', $slug . ':' . $version, $sourceUrl, new DateTimeImmutable(), 'sha256', $files ) );
		} finally {
			if ( $opened ) {
				$zip->close();
			}
		}
	}
}
