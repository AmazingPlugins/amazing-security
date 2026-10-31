<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Integrity\WordPressOrgManifestProvider;
use PHPUnit\Framework\TestCase;

final class ManifestTest extends TestCase {
	public function test_core_manifest_rejects_unsafe_paths_before_use(): void {
		$client = new class() implements HttpClient {
			public function get( string $url, int $maxBytes ): HttpResult {
				return new HttpResult( 200, '{"checksums":{"../wp-config.php":"' . str_repeat( 'a', 32 ) . '"}}' );
			}
		};
		$result = ( new WordPressOrgManifestProvider( $client ) )->core( '6.6', 'en_US' );
		self::assertNull( $result->manifest );
		self::assertSame( 'invalid_manifest', $result->reason );
	}

	public function test_plugin_prefers_sha256_and_accepts_multiple_hashes(): void {
		$client = new class() implements HttpClient {
			public function get( string $url, int $maxBytes ): HttpResult {
				return new HttpResult( 200, '{"files":{"akismet.php":{"sha256":["' . str_repeat( 'a', 64 ) . '","' . str_repeat( 'b', 64 ) . '"],"md5":"' . str_repeat( 'c', 32 ) . '"}}}' );
			}
		};
		$result = ( new WordPressOrgManifestProvider( $client ) )->plugin( 'akismet', '5.3.1' );
		self::assertSame( 'sha256', $result->manifest->algorithm );
		self::assertCount( 2, $result->manifest->files['akismet.php'] );
	}

	public function test_wrong_locale_manifest_cannot_be_reused(): void {
		$client   = new class() implements HttpClient {
			public array $urls = array();
			public function get( string $url, int $maxBytes ): HttpResult {
				$this->urls[] = $url;
				return new HttpResult( 200, '{"checksums":{"index.php":"' . str_repeat( 'a', 32 ) . '"}}' );
			}
		};
		$provider = new WordPressOrgManifestProvider( $client );
		$provider->core( '6.6', 'en_US' );
		$provider->core( '6.6', 'de_DE' );
		self::assertCount( 2, $client->urls );
		self::assertStringContainsString( 'locale=de_DE', $client->urls[1] );
	}
}
