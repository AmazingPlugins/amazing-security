<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

use AmazingPlugins\Security\Integrity\WordPressOptions;
final class WordPressExposureService {
	public function create(): ExposureService {
		return new ExposureService( new WordPressOptions(), new ExposureScanner(), array( $this, 'root' ) );}
	public function root( string $alias ): ?string {
		if ( 'site' === $alias ) {
			return ABSPATH;}
		if ( 'content' === $alias ) {
			$path = WP_CONTENT_DIR;
		} elseif ( 'uploads' === $alias ) {
			$uploads = wp_upload_dir( null, false );
			$path    = is_string( $uploads['basedir'] ?? null ) && empty( $uploads['error'] ) ? $uploads['basedir'] : null;
		} else {
			return null;}
		if ( ! is_string( $path ) || str_contains( $path, '://' ) ) {
			return null;
		}$site = realpath( ABSPATH );
		$root  = realpath( $path );
		if ( false === $site || false === $root || '/' === $root || $site === $root || str_starts_with( $site, $root . '/' ) ) {
			return null;}
		if ( 'uploads' === $alias ) {
			$excluded = array( WP_CONTENT_DIR, ABSPATH . '/wp-admin', ABSPATH . '/wp-includes', WP_CONTENT_DIR . '/plugins', WP_CONTENT_DIR . '/mu-plugins', WP_CONTENT_DIR . '/themes' );
			foreach ( array( 'WP_PLUGIN_DIR', 'WPMU_PLUGIN_DIR' ) as $constant ) {
				if ( defined( $constant ) ) {
					$excluded[] = constant( $constant ); }
			}
			if ( function_exists( 'get_theme_root' ) ) {
				$excluded[] = get_theme_root(); }
			global $wp_theme_directories;
			if ( is_array( $wp_theme_directories ) ) {
				$excluded = array_merge( $excluded, $wp_theme_directories ); }
			foreach ( $excluded as $index => $directory ) {
				$canonical = is_string( $directory ) ? realpath( $directory ) : false;
				if ( false === $canonical ) {
					continue; }
				// Content descendants are allowed, but content itself and its ancestors are not.
				if ( $root === $canonical || str_starts_with( $canonical, $root . '/' ) || ( 0 !== $index && str_starts_with( $root, $canonical . '/' ) ) ) {
					return null; }
			}
		}
		return $path;
	}
}
