<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

defined( 'ABSPATH' ) || exit;

final class WordPressOrgThemeManifestProvider implements ThemeManifestProvider {
	/** @var \Closure(string): ?string Downloads a URL to a temp file and returns its path. */
	private readonly \Closure $download;

	public function __construct( private readonly ThemeArchiveParser $parser, ?\Closure $download = null ) {
		$this->download = $download ?? static function ( string $url ): ?string {
			if ( ! function_exists( 'download_url' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}
			$path = download_url( $url, 30 );
			return is_string( $path ) ? $path : null;
		};
	}

	public function theme( string $slug, string $version ): ManifestResult {
		if ( ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug ) || ! preg_match( '/^[0-9]+(?:\.[0-9A-Za-z-]+)*$/D', $version ) ) {
			return new ManifestResult( null, 'unsupported_identity' );
		}
		$url = 'https://downloads.wordpress.org/theme/' . $slug . '.' . $version . '.zip';
		$key = 'amazing_security_theme_' . substr( hash( 'sha256', $slug . ':' . $version ), 0, 40 );
		if ( function_exists( 'get_transient' ) ) {
			$cached = get_transient( $key );
			if ( $cached instanceof Manifest && $cached->identity === $slug . ':' . $version && $cached->sourceUrl === $url && $cached->fetchedAt->getTimestamp() >= time() - DAY_IN_SECONDS ) {
				return new ManifestResult( $cached );
			}
		}
		$path = ( $this->download )( $url );
		if ( null === $path ) {
			return new ManifestResult( null, 'unavailable' );
		}
		try {
			$result = $this->parser->parse( $slug, $version, $path, $url );
		} finally {
			wp_delete_file( $path );
		}
		if ( null !== $result->manifest && function_exists( 'set_transient' ) ) {
			set_transient( $key, $result->manifest, DAY_IN_SECONDS );
		}
		return $result;
	}
}
