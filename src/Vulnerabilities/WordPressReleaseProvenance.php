<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\WordPressHttpClient;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;

final class WordPressReleaseProvenance {
	public function verify( InstalledSoftware $item ): bool {
		if ( 'plugin' !== $item->type || ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $item->slug ) || ! function_exists( 'get_plugins' ) ) {
			return false;
		}
		$matches = 0;
		foreach ( get_plugins() as $file => $details ) {
			if ( dirname( $file ) === $item->slug ) {
				if ( '' !== (string) ( $details['UpdateURI'] ?? '' ) || (string) ( $details['Version'] ?? '' ) !== $item->version ) {
					return false;
				}
				++$matches;
			}
		}
		if ( 1 !== $matches ) {
			return false;
		}
		$manifest = ( new WordPressOrgManifestProvider( new WordPressHttpClient() ) )->plugin( $item->slug, $item->version )->manifest;
		return null !== $manifest && ( new ReleaseProvenance() )->verify( $manifest, WP_PLUGIN_DIR . '/' . $item->slug );
	}
}
