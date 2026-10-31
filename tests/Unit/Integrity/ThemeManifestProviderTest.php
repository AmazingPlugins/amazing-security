<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\ThemeArchiveParser;
use AmazingPlugins\Security\Integrity\WordPressOrgThemeManifestProvider;
use PHPUnit\Framework\TestCase;
use ZipArchive;

final class ThemeManifestProviderTest extends TestCase {
	public function test_rejects_identity_without_network_request(): void {
		$calls    = 0;
		$provider = new WordPressOrgThemeManifestProvider(
			new ThemeArchiveParser(),
			static function () use ( &$calls ): ?string {
				++$calls;
				return null;
			}
		);
		self::assertSame( 'unsupported_identity', $provider->theme( '../evil', '1.0' )->reason );
		self::assertSame( 'unsupported_identity', $provider->theme( 'safe', '../../x' )->reason );
		self::assertSame( 0, $calls );
	}

	public function test_downloads_exact_archive_and_deletes_it(): void {
		$path = tempnam( sys_get_temp_dir(), 'amsec-provider-' );
		$zip  = new ZipArchive();
		self::assertTrue( $zip->open( $path, ZipArchive::OVERWRITE ) );
		$zip->addFromString( 'sample/style.css', 'css' );
		$zip->close();
		$requested = '';
		$provider  = new WordPressOrgThemeManifestProvider(
			new ThemeArchiveParser(),
			static function ( string $url ) use ( &$requested, $path ): string {
				$requested = $url;
				return $path;
			}
		);
		$result = $provider->theme( 'sample', '1.2' );
		self::assertSame( 'https://downloads.wordpress.org/theme/sample.1.2.zip', $requested );
		self::assertSame( array( hash( 'sha256', 'css' ) ), $result->manifest->files['style.css'] );
		self::assertFileDoesNotExist( $path );
	}

	public function test_failed_download_is_unavailable(): void {
		$provider = new WordPressOrgThemeManifestProvider( new ThemeArchiveParser(), static fn(): ?string => null );
		self::assertSame( 'unavailable', $provider->theme( 'sample', '1.2' )->reason );
	}
}
