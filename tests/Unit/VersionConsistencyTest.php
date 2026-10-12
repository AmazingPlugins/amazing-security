<?php
namespace AmazingPlugins\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class VersionConsistencyTest extends TestCase {
	public function test_header_constant_and_readme_stable_tag_agree(): void {
		$root   = dirname( __DIR__, 2 );
		$main   = (string) file_get_contents( $root . '/amazing-security.php' );
		$readme = (string) file_get_contents( $root . '/readme.txt' );
		preg_match( '/^ \* Version: (\S+)/m', $main, $header );
		preg_match( "/define\( 'AMAZING_SECURITY_VERSION', '([^']+)' \)/", $main, $constant );
		preg_match( '/^Stable tag: (\S+)/m', $readme, $stable );
		self::assertNotEmpty( $header[1] ?? '' );
		self::assertSame( $header[1], $constant[1] ?? null );
		self::assertSame( $header[1], $stable[1] ?? null );
	}

	public function test_asset_versions_use_the_constant(): void {
		$bad = array();
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( dirname( __DIR__, 2 ) . '/src', \FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			if ( 'php' === $file->getExtension() && 1 === preg_match( "/AMAZING_SECURITY_FILE \), array\([^)]*\), '[0-9.]+'/", (string) file_get_contents( $file->getPathname() ) ) ) {
				$bad[] = $file->getPathname();
			}
		}
		self::assertSame( array(), $bad );
	}

	public function test_no_third_party_font_host_is_loaded(): void {
		self::assertStringNotContainsString( 'fonts.googleapis.com', (string) file_get_contents( dirname( __DIR__, 2 ) . '/src/Admin/Brand.php' ) );
	}
}
