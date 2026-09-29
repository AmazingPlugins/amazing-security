<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Integrity\ThemeArchiveParser;
use AmazingPlugins\Security\Integrity\WordPressOrgThemeManifestProvider;
use PHPUnit\Framework\TestCase;
use ZipArchive;

final class ThemeManifestProviderTest extends TestCase {
	public function test_rejects_identity_without_network_request(): void {
		$client = new class implements HttpClient {
			public int $calls = 0;
			public function get( string $url, int $maxBytes ): HttpResult {
				++$this->calls;
				return new HttpResult( 404, '' );
			}
		};
		$provider = new WordPressOrgThemeManifestProvider( $client, new ThemeArchiveParser() );
		self::assertSame( 'unsupported_identity', $provider->theme( '../evil', '1.0' )->reason );
		self::assertSame( 'unsupported_identity', $provider->theme( 'safe', '../../x' )->reason );
		self::assertSame( 0, $client->calls );
	}

	public function test_requests_exact_archive_under_network_cap(): void {
		$path = tempnam( sys_get_temp_dir(), 'amsec-provider-' );
		$zip = new ZipArchive();
		self::assertTrue( $zip->open( $path, ZipArchive::OVERWRITE ) );
		$zip->addFromString( 'sample/style.css', 'css' );
		$zip->close();
		$body = file_get_contents( $path );
		unlink( $path );
		$client = new class( $body ) implements HttpClient {
			public string $url = '';
			public int $limit = 0;
			public function __construct( private readonly string $body ) {}
			public function get( string $url, int $maxBytes ): HttpResult {
				$this->url = $url;
				$this->limit = $maxBytes;
				return new HttpResult( 200, $this->body );
			}
		};
		$result = ( new WordPressOrgThemeManifestProvider( $client, new ThemeArchiveParser() ) )->theme( 'sample', '1.2' );
		self::assertSame( 'https://downloads.wordpress.org/theme/sample.1.2.zip', $client->url );
		self::assertSame( 16777216, $client->limit );
		self::assertSame( array( hash( 'sha256', 'css' ) ), $result->manifest->files['style.css'] );
	}
}
