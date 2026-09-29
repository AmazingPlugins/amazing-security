<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class WordPressReleaseProvenance {
	public function verify( InstalledSoftware $item ): bool {
		return null !== $this->proof( $item );
	}

	public function proof( InstalledSoftware $item ): ?string {
		if ( 'plugin' !== $item->type || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $item->slug ) || ! function_exists( 'get_plugins' ) ) {
			return null;
		}
		$matches = 0;
		foreach ( get_plugins() as $file => $details ) {
			if ( dirname( $file ) === $item->slug ) {
				if ( '' !== (string) ( $details['UpdateURI'] ?? '' ) || (string) ( $details['Version'] ?? '' ) !== $item->version ) {
					return null;
				}
				++$matches;
			}
		}
		if ( 1 !== $matches ) {
			return null;
		}
		$manifest = ( new WordPressOrgManifestProvider( new WordPressHttpClient() ) )->plugin( $item->slug, $item->version )->manifest;
		if ( null === $manifest ) {
			return null;
		}
		$checker = new ReleaseProvenance();
		$root    = WP_PLUGIN_DIR . '/' . $item->slug;
		$before  = $checker->fileState( $root );
		if ( null === $before || ! $checker->verify( $manifest, $root ) || $before !== $checker->fileState( $root ) ) {
			return null;
		}
		return time() . ':' . $before;
	}

	public function stillMatches( InstalledSoftware $item, string $proof ): bool {
		if ( 'plugin' !== $item->type || ! preg_match( '/^([0-9]{10}):([a-f0-9]{64})$/D', $proof, $matches ) || (int) $matches[1] < time() - HOUR_IN_SECONDS ) {
			return false;
		}
		$current = ( new ReleaseProvenance() )->fileState( WP_PLUGIN_DIR . '/' . $item->slug );
		return null !== $current && hash_equals( $matches[2], $current );
	}
}
