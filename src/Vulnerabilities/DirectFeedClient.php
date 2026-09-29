<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Vulnerabilities;

use AmazingPlugins\Security\Integrity\HttpClient;

final class DirectFeedClient {
	public function __construct( private readonly HttpClient $http, private readonly DirectFeedCache $cache ) {}

	public function lookup( string $type, string $slug, int $now ): ?DirectFeedResponse {
		if ( ! $this->valid( $type, $slug ) ) {
			return null;
		}
		$key    = $type . ':' . $slug;
		$cached = $this->cached( $type, $slug, $now );
		if ( null !== $cached ) {
			return $cached;
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

	public function cached( string $type, string $slug, int $now ): ?DirectFeedResponse {
		if ( ! $this->valid( $type, $slug ) ) {
			return null;
		}
		$cached = $this->cache->get( $type . ':' . $slug );
		return null !== $cached && $cached['fetched_at'] <= $now && $cached['fetched_at'] >= $now - 86400 ? DirectFeedResponse::parse( $type, $slug, $cached['body'], $cached['fetched_at'] ) : null;
	}

	private function valid( string $type, string $slug ): bool {
		$validSlug = 'core' === $type ? (bool) preg_match( '/^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/D', $slug ) : (bool) preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug );
		return in_array( $type, array( 'core', 'plugin', 'theme' ), true ) && $validSlug;
	}
}
