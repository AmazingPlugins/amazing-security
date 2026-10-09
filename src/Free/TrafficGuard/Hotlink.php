<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\TrafficGuard;

/** Uploads image requests with an external HTTP referrer. */
final class Hotlink {
	public function blocked( bool $enabled, array $server, string $site_host ): bool {
		if ( ! $enabled ) {
			return false;
		}
		$uri = $server['REQUEST_URI'] ?? '';
		if ( ! is_string( $uri ) || ! $this->isUploadsImage( $uri ) ) {
			return false;
		}
		$referrer = $server['HTTP_REFERER'] ?? '';
		if ( ! is_string( $referrer ) || '' === trim( $referrer ) ) {
			return false;
		}
		$parts  = $this->parseUrl( $referrer );
		$scheme = isset( $parts['scheme'] ) && is_string( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : '';
		$host   = isset( $parts['host'] ) && is_string( $parts['host'] ) ? strtolower( $parts['host'] ) : '';
		$site   = $this->siteHost( $site_host );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || '' === $host || '' === $site || $host === $site ) {
			return false;
		}
		return true;
	}

	public function isUploadsImage( string $uri ): bool {
		$cut  = strcspn( $uri, '?#' );
		$path = substr( $uri, 0, $cut );
		return 1 === preg_match( '#/uploads/.+\.(jpe?g|png|gif|webp)\z#i', $path );
	}

	/**
	 * Host comparison uses wp_parse_url when WordPress is loaded.
	 *
	 * @return array<string, mixed>
	 */
	private function parseUrl( string $url ): array {
		if ( function_exists( 'wp_parse_url' ) ) {
			$parts = wp_parse_url( $url );
			return is_array( $parts ) ? $parts : array();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Unit tests call this without WordPress loaded.
		$parts = parse_url( $url );
		return is_array( $parts ) ? $parts : array();
	}

	private function siteHost( string $site_host ): string {
		$site_host = strtolower( trim( $site_host ) );
		if ( str_contains( $site_host, '://' ) ) {
			$parts = $this->parseUrl( $site_host );
			$host  = $parts['host'] ?? '';
			return is_string( $host ) ? strtolower( $host ) : '';
		}
		return $site_host;
	}
}
