<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

use DateTimeImmutable;

final class WordPressOrgManifestProvider implements ChecksumManifestProvider {
	public function __construct( private readonly HttpClient $client ) {}

	public function core( string $version, string $locale ): ManifestResult {
		if ( ! preg_match( '/^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/D', $version ) || ! preg_match( '/^[a-z]{2,3}_[A-Z]{2}$/D', $locale ) ) {
			return new ManifestResult( null, 'unsupported_identity' );
		}
		$url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $version ) . '&locale=' . rawurlencode( $locale );
		return $this->fetch( 'core', $version . ':' . $locale, $url, 'checksums' );
	}

	public function plugin( string $slug, string $version ): ManifestResult {
		if ( ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) || ! preg_match( '/^[0-9]+(?:\.[0-9A-Za-z-]+)*$/D', $version ) ) {
			return new ManifestResult( null, 'unsupported_identity' );
		}
		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		return $this->fetch( 'plugin', $slug . ':' . $version, $url, 'files' );
	}

	private function fetch( string $type, string $identity, string $url, string $key ): ManifestResult {
		$cacheKey = 'amsec_security_scanner_checksum_' . substr( hash( 'sha256', $type . ':' . $identity ), 0, 40 );
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $cacheKey );
			if ( $cached instanceof Manifest && $cached->identity === $identity && $cached->sourceUrl === $url && $cached->fetchedAt->getTimestamp() >= time() - DAY_IN_SECONDS ) {
				return new ManifestResult( $cached );
			}
		}
		$max      = 4 * 1024 * 1024;
		$response = $this->client->get( $url, $max );
		if ( 200 !== $response->status ) {
			return new ManifestResult( null, 'unavailable' );
		}
		if ( strlen( $response->body ) > $max ) {
			return new ManifestResult( null, 'oversized_manifest' );
		}
		$data = json_decode( $response->body, true );
		if ( ! is_array( $data ) || ! isset( $data[ $key ] ) || ! is_array( $data[ $key ] ) || count( $data[ $key ] ) > 10000 || array() === $data[ $key ] ) {
			return new ManifestResult( null, 'invalid_manifest' );
		}
		$files     = array();
		$algorithm = null;
		foreach ( $data[ $key ] as $path => $entry ) {
			if ( ! is_string( $path ) || ! self::safePath( $path ) ) {
				return new ManifestResult( null, 'invalid_manifest' );
			}
			if ( 'core' === $type && str_starts_with( $path, 'wp-content/' ) ) {
				continue;
			}
			if ( 'plugin' === $type ) {
				if ( ! is_array( $entry ) ) {
					return new ManifestResult( null, 'invalid_manifest' );
				}
				$fileAlgorithm = isset( $entry['sha256'] ) ? 'sha256' : 'md5';
				if ( null !== $algorithm && $fileAlgorithm !== $algorithm ) {
					return new ManifestResult( null, 'invalid_manifest' );
				}
				$algorithm = $fileAlgorithm;
				$entry     = $entry[ $algorithm ] ?? null;
			}
			$algorithm ??= 'md5';
			$digests     = is_array( $entry ) ? $entry : array( $entry );
			if ( array() === $digests ) {
				return new ManifestResult( null, 'invalid_manifest' );
			}
			foreach ( $digests as $digest ) {
				if ( ! is_string( $digest ) || ! preg_match( '/^[a-f0-9]{' . ( 'sha256' === $algorithm ? '64' : '32' ) . '}$/Di', $digest ) ) {
					return new ManifestResult( null, 'invalid_manifest' );
				}
			}
			$files[ $path ] = array_map( 'strtolower', $digests );
		}
		$manifest = new Manifest( $type, $identity, $url, new DateTimeImmutable( 'now' ), $algorithm, $files );
		if ( function_exists( 'set_transient' ) ) {
			set_transient( $cacheKey, $manifest, DAY_IN_SECONDS );
		}
		return new ManifestResult( $manifest );
	}

	public static function safePath( string $path ): bool {
		return '' !== $path && ! str_contains( $path, '\\' ) && ! str_starts_with( $path, '/' ) && ! str_contains( $path, "\0" ) && ! preg_match( '/^[A-Za-z]:/', $path ) && ! in_array( '..', explode( '/', $path ), true ) && ! in_array( '.', explode( '/', $path ), true ) && ! in_array( '', explode( '/', $path ), true );
	}
}
