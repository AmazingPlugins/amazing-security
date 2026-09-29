<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Repair;

use AmazingPlugins\Security\Integrity\ChecksumManifestProvider;
use AmazingPlugins\Security\Integrity\HttpClient;
use ZipArchive;

final class PluginRepairSource {
	public function __construct( private readonly ChecksumManifestProvider $manifests, private readonly HttpClient $http ) {}

	public function fetch( RepairCandidate $candidate ): ?RepairBytes {
		if ( ! class_exists( ZipArchive::class ) ) {
			return null;
		}
		$result   = $this->manifests->plugin( $candidate->slug, $candidate->version );
		$manifest = $result->manifest;
		if ( null === $manifest || 'plugin' !== $manifest->type || $candidate->slug . ':' . $candidate->version !== $manifest->identity || ! in_array( $manifest->algorithm, array( 'md5', 'sha256' ), true ) ) {
			return null;
		}
		$expected = $manifest->files[ $candidate->relativePath ] ?? null;
		if ( ! is_array( $expected ) || array() === $expected ) {
			return null;
		}
		$url     = 'https://downloads.wordpress.org/plugin/' . $candidate->slug . '.' . $candidate->version . '.zip';
		$archive = $this->http->get( $url, 16777216 );
		if ( 200 !== $archive->status || '' === $archive->body || strlen( $archive->body ) > 16777216 ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_tempnam -- ZipArchive needs a seekable file outside the site.
		$temp = tempnam( sys_get_temp_dir(), 'amsec-repair-' );
		if ( false === $temp ) {
			return null;
		}
		$zip    = new ZipArchive();
		$opened = false;
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Private temporary archive, never extracted into the site.
			if ( strlen( $archive->body ) !== file_put_contents( $temp, $archive->body ) ) {
				return null;
			}
			$opened = true === $zip->open( $temp, ZipArchive::RDONLY );
			if ( ! $opened || $zip->numFiles > 10000 ) {
				return null;
			}
			$name = $candidate->slug . '/' . $candidate->relativePath;
			$stat = $zip->statName( $name );
			if ( false === $stat || ! isset( $stat['size'], $stat['comp_size'] ) || $stat['size'] < 0 || $stat['size'] > 2097152 || ( $stat['size'] > 0 && $stat['size'] > 100 * max( 1, $stat['comp_size'] ) ) ) {
				return null;
			}
			$index = $zip->locateName( $name );
			if ( false === $index ) {
				return null;
			}
			$zip->getExternalAttributesIndex( $index, $opsys, $attributes );
			if ( isset( $opsys, $attributes ) && ZipArchive::OPSYS_UNIX === $opsys && 0120000 === ( ( $attributes >> 16 ) & 0170000 ) ) {
				return null;
			}
			$stream = $zip->getStream( $name );
			if ( false === $stream ) {
				return null;
			}
			$contents = '';
			try {
				$read = 0;
				while ( ! feof( $stream ) && $read <= 2097152 ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded archive entry stream.
					$chunk = fread( $stream, 65536 );
					if ( false === $chunk ) {
						return null;
					}
					$contents .= $chunk;
					$read     += strlen( $chunk );
				}
			} finally {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Close archive entry stream.
				fclose( $stream );
			}
			if ( strlen( $contents ) !== $stat['size'] || ! in_array( hash( $manifest->algorithm, $contents ), $expected, true ) ) {
				return null;
			}
			return new RepairBytes( $contents, hash( 'sha256', $contents ), $url );
		} finally {
			if ( $opened ) {
				$zip->close();
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Delete only the private temporary archive created here.
			unlink( $temp );
		}
	}
}
