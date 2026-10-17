<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Baseline;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class TargetResolver {
	public function targets(): array {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$targets = array();
		foreach ( array_slice( array_keys( get_plugins() ), 0, 200 ) as $file ) {
			if ( ! WordPressOrgManifestProvider::safePath( $file ) ) {
				continue;
			}
			$dir                       = dirname( $file );
			$target                    = new BaselineTarget( 'plugin', $file, '.' === $dir ? WP_PLUGIN_DIR : WP_PLUGIN_DIR . '/' . $dir, '.' === $dir ? basename( $file ) : null );
			$targets[ $target->key() ] = $target;
		}
		foreach ( array_slice( wp_get_themes(), 0, 200, true ) as $slug => $theme ) {
			if ( WordPressOrgManifestProvider::safePath( $slug ) ) {
				$target                    = new BaselineTarget( 'theme', $slug, rtrim( $theme->get_stylesheet_directory(), '/' ) );
				$targets[ $target->key() ] = $target;
			}
		}
		foreach ( array_slice( array_keys( get_mu_plugins() ), 0, 200 ) as $file ) {
			if ( WordPressOrgManifestProvider::safePath( $file ) && ! str_contains( $file, '/' ) ) {
				$target                    = new BaselineTarget( 'mu-plugin', $file, WPMU_PLUGIN_DIR, $file );
				$targets[ $target->key() ] = $target;
			}
		}
		return $targets;
	}

	public function resolve( string $key ): BaselineTarget {
		$target = $this->targets()[ $key ] ?? null;
		if ( ! $target instanceof BaselineTarget || strlen( $key ) > 256 ) {
			throw new \RuntimeException( 'Selected package unavailable.' );
		}
		return $target;
	}
}
