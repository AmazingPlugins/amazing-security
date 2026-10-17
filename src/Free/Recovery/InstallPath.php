<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Recovery;

defined( 'ABSPATH' ) || exit;

/** Resolves a relative path inside a WordPress install without following links. */
final class InstallPath {
	private readonly string $root;

	public function __construct( string $root ) {
		$trimmed    = rtrim( $root, '/\\' );
		$this->root = '' === $trimmed ? $root : $trimmed;
	}

	public static function inside( string $path, string $root ): bool {
		$path = rtrim( str_replace( '\\', '/', $path ), '/' );
		$root = rtrim( str_replace( '\\', '/', $root ), '/' );
		return '' !== $root && ( $path === $root || str_starts_with( $path, $root . '/' ) );
	}

	public function regularFile( string $relative ): ?string {
		$walked = $this->walk( $relative );
		if ( null === $walked ) {
			return null;
		}
		clearstatcache( true, $walked );
		if ( is_link( $walked ) || ! is_file( $walked ) ) {
			return null;
		}
		$real = realpath( $walked );
		$root = realpath( $this->root );
		if ( false === $real || false === $root || ! self::inside( $real, $root ) || $real === $root ) {
			return null;
		}
		return $real;
	}

	private function walk( string $relative ): ?string {
		if ( '' === $relative || str_contains( $relative, '..' ) || str_contains( $relative, "\0" ) || str_contains( $relative, '\\' ) ) {
			return null;
		}
		if ( 1 !== preg_match( '#\A[A-Za-z0-9_./-]+\z#', $relative ) ) {
			return null;
		}
		$root = realpath( $this->root );
		if ( false === $root || ! is_dir( $root ) ) {
			return null;
		}
		$path = $root;
		foreach ( explode( '/', $relative ) as $part ) {
			if ( '' === $part || '.' === $part || '..' === $part ) {
				return null;
			}
			$path .= '/' . $part;
			if ( is_link( $path ) ) {
				return null;
			}
		}
		return $path;
	}
}
