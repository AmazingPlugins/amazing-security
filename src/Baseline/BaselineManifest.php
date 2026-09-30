<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class BaselineManifest {
	public readonly array $files;

	public function __construct( array $files ) {
		if ( count( $files ) > 300 ) {
			throw new \RuntimeException( 'Baseline exceeds its file budget.' );
		}
		foreach ( $files as $path => $hash ) {
			if ( ! is_string( $path ) || strlen( $path ) > 512 || ! WordPressOrgManifestProvider::safePath( $path ) || ! is_string( $hash ) || ! preg_match( '/^[a-f0-9]{64}$/D', $hash ) ) {
				throw new \RuntimeException( 'Invalid baseline manifest.' );
			}
		}
		ksort( $files, SORT_STRING );
		$this->files = $files;
	}

	public function fingerprint(): string {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Deterministic pure-PHP manifest hashing.
		return hash( 'sha256', json_encode( $this->files, JSON_THROW_ON_ERROR ) );
	}

	public function compare( self $current ): array {
		$added    = array_keys( array_diff_key( $current->files, $this->files ) );
		$deleted  = array_keys( array_diff_key( $this->files, $current->files ) );
		$modified = array();
		foreach ( array_intersect_key( $current->files, $this->files ) as $path => $hash ) {
			if ( ! hash_equals( $this->files[ $path ], $hash ) ) {
				$modified[] = $path;
			}
		}
		return array(
			'added'    => $added,
			'modified' => $modified,
			'deleted'  => $deleted,
		);
	}
}
