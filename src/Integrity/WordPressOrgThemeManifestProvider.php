<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Integrity;

final class WordPressOrgThemeManifestProvider implements ThemeManifestProvider {
	public function __construct( private readonly HttpClient $client, private readonly ThemeArchiveParser $parser ) {}

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
		$response = $this->client->get( $url, 16777216 );
		if ( 200 !== $response->status ) {
			return new ManifestResult( null, 'unavailable' );
		}
		$result = $this->parser->parse( $slug, $version, $response->body, $url );
		if ( null !== $result->manifest && function_exists( 'set_transient' ) ) {
			set_transient( $key, $result->manifest, DAY_IN_SECONDS );
		}
		return $result;
	}
}
