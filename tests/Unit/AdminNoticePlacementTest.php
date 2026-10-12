<?php
namespace AmazingPlugins\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class AdminNoticePlacementTest extends TestCase {
	/** WordPress moves notices without the inline class above our header. Our own messages must stay in their panel. */
	public function test_plugin_messages_use_the_inline_notice_class(): void {
		$bad = array();
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( dirname( __DIR__, 2 ) . '/src', \FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			if ( 'php' === $file->getExtension() && 1 === preg_match( '/class="notice(?![^"]*\binline\b)[^"]*"/', (string) file_get_contents( $file->getPathname() ) ) ) {
				$bad[] = $file->getPathname();
			}
		}
		self::assertSame( array(), $bad );
	}

	public function test_brand_bar_prints_the_header_end_marker_before_the_bar(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/src/Admin/Brand.php' );
		self::assertGreaterThan( 0, strpos( $source, 'wp-header-end' ) );
		self::assertLessThan( strpos( $source, 'amsec-brand"' ), strpos( $source, 'wp-header-end' ) );
	}

	public function test_header_uses_the_shield_mark(): void {
		self::assertFileExists( dirname( __DIR__, 2 ) . '/assets/logo-shield.svg' );
		self::assertStringContainsString( 'logo-shield.svg', (string) file_get_contents( dirname( __DIR__, 2 ) . '/src/Admin/Brand.php' ) );
	}
}
