<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Vulnerabilities\DirectFeedCache;
use AmazingPlugins\Security\Vulnerabilities\DirectFeedClient;
use PHPUnit\Framework\TestCase;

final class DirectFeedClientTest extends TestCase {
	public function test_fetches_fixed_component_url_then_uses_local_cache(): void {
		$json   = file_get_contents( dirname( __DIR__, 2 ) . '/Fixtures/WPVulnerability/plugin-akismet.json' );
		$http   = new class( $json ) implements HttpClient {
			public array $urls = array();
			public function __construct( private string $json ) {}
			public function get( string $url, int $maxBytes ): HttpResult {
				$this->urls[] = $url;
				return new HttpResult( 200, $this->json );
			}
		};
		$cache  = new class() implements DirectFeedCache {
			public array $values = array();
			public function get( string $key ): ?array {
				return $this->values[ $key ] ?? null; }
			public function put( string $key, string $body, int $fetchedAt ): void {
				$this->values[ $key ] = array(
					'body'       => $body,
					'fetched_at' => $fetchedAt,
				); }
		};
		$client = new DirectFeedClient( $http, $cache );
		self::assertNotNull( $client->lookup( 'plugin', 'akismet', 1790676000 ) );
		self::assertNotNull( $client->lookup( 'plugin', 'akismet', 1790676200 ) );
		self::assertNotNull( $client->cached( 'plugin', 'akismet', 1790676200 ) );
		self::assertSame( array( 'https://www.wpvulnerability.net/plugin/akismet/' ), $http->urls );
	}

	public function test_rejects_invalid_slug_and_failed_response(): void {
		$http   = new class() implements HttpClient {
			public array $urls = array();
			public function get( string $url, int $maxBytes ): HttpResult {
				$this->urls[] = $url;
				return new HttpResult( 503, '' ); }
		};
		$cache  = new class() implements DirectFeedCache {
			public function get( string $key ): ?array {
				return null; }
			public function put( string $key, string $body, int $fetchedAt ): void {}
		};
		$client = new DirectFeedClient( $http, $cache );
		self::assertNull( $client->lookup( 'plugin', '../evil', 1790676000 ) );
		self::assertNull( $client->lookup( 'plugin', 'akismet', 1790676000 ) );
		self::assertSame( array( 'https://www.wpvulnerability.net/plugin/akismet/' ), $http->urls );
	}
}
