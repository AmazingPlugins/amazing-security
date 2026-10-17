<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\FileReader;
use AmazingPlugins\Security\Integrity\IntegrityBudget;
use AmazingPlugins\Security\Integrity\Manifest;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class ReleaseProvenance {
	public function __construct( private readonly FileReader $reader = new FileReader() ) {}

	public function fileState( string $root ): ?string {
		if ( is_link( $root ) || ! is_dir( $root ) ) {
			return null;
		}
		$base = realpath( $root );
		if ( false === $base ) {
			return null;
		}
		$paths = array();
		try {
			$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $files as $file ) {
				if ( count( $paths ) >= 250 || $file->isLink() || ! $file->isFile() ) {
					return null;
				}
				$paths[] = str_replace( DIRECTORY_SEPARATOR, '/', substr( $file->getPathname(), strlen( $base ) + 1 ) );
			}
		} catch ( \Throwable $error ) {
			return null;
		}
		sort( $paths );
		$budget = new IntegrityBudget( 250, 33554432, 5.0, 5.0 );
		$hash   = hash_init( 'sha256' );
		foreach ( $paths as $path ) {
			$result = $this->reader->hash( $base, $path, 'sha256', $budget );
			if ( 'ok' !== $result->state ) {
				return null;
			}
			hash_update( $hash, $path . "\0" . $result->digest . "\0" );
		}
		return hash_final( $hash );
	}

	public function verify( Manifest $manifest, string $root ): bool {
		if ( 'plugin' !== $manifest->type || 'sha256' !== $manifest->algorithm || array() === $manifest->files || count( $manifest->files ) > 250 || is_link( $root ) || ! is_dir( $root ) ) {
			return false;
		}
		$budget = new IntegrityBudget( 250, 33554432, 5.0, 5.0 );
		foreach ( $manifest->files as $path => $digests ) {
			$result = $this->reader->hash( $root, $path, $manifest->algorithm, $budget );
			if ( 'ok' !== $result->state || ! in_array( $result->digest, $digests, true ) ) {
				return false;
			}
		}
		$base = realpath( $root );
		if ( false === $base ) {
			return false;
		}
		$count = 0;
		try {
			$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $files as $file ) {
				if ( ++$count > 1000 || ! $budget->hasTime() || $file->isLink() || ! $file->isFile() ) {
					return false;
				}
				$relative = substr( $file->getPathname(), strlen( $base ) + 1 );
				if ( ! array_key_exists( str_replace( DIRECTORY_SEPARATOR, '/', $relative ), $manifest->files ) ) {
					return false;
				}
			}
		} catch ( \Throwable $error ) {
			return false;
		}
		return count( $manifest->files ) === $count;
	}
}
