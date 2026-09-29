<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\HttpClient;

final class DirectFeedClient {
	public function __construct( private readonly HttpClient $http, private readonly DirectFeedCache $cache ) {}

	public function lookup( string $type, string $slug, int $now ): ?DirectFeedResponse {
		$validSlug = 'core' === $type ? (bool) preg_match( '/^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/D', $slug ) : (bool) preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug );
		if ( ! in_array( $type, array( 'core', 'plugin', 'theme' ), true ) || ! $validSlug ) {
			return null;
		}
		$key    = $type . ':' . $slug;
		$cached = $this->cache->get( $key );
		if ( null !== $cached && $cached['fetched_at'] <= $now && $cached['fetched_at'] >= $now - 86400 ) {
			$parsed = DirectFeedResponse::parse( $type, $slug, $cached['body'], $cached['fetched_at'] );
			if ( null !== $parsed ) {
				return $parsed;
			}
		}
		$url      = 'https://www.wpvulnerability.net/' . $type . '/' . rawurlencode( $slug ) . '/';
		$response = $this->http->get( $url, 512 * 1024 );
		if ( 200 !== $response->status ) {
			return null;
		}
		$parsed = DirectFeedResponse::parse( $type, $slug, $response->body, $now );
		if ( null !== $parsed ) {
			$this->cache->put( $key, $response->body, $now );
		}
		return $parsed;
	}
}
