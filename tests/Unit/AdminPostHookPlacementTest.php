<?php
namespace AmazingPlugins\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class AdminPostHookPlacementTest extends TestCase {
	/** admin-post.php never fires admin_menu, so a handler hooked beside a menu entry never runs. */
	public function test_admin_post_handlers_are_not_registered_in_menu_callbacks(): void {
		$bad = array();
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( dirname( __DIR__, 2 ) . '/src', \FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			if ( 'php' !== $file->getExtension() ) {
				continue;
			}
			$source = (string) file_get_contents( $file->getPathname() );
			if ( 1 === preg_match_all( '/function register\(.*?\n\t}\n/s', $source, $methods ) ) {
				foreach ( $methods[0] as $body ) {
					if ( str_contains( $body, "'admin_post_" ) ) {
						$bad[] = $file->getPathname();
					}
				}
			}
		}
		self::assertSame( array(), $bad );
	}

	public function test_activity_and_uploads_rule_handlers_are_hooked_at_load_time(): void {
		$main = (string) file_get_contents( dirname( __DIR__, 2 ) . '/amazing-security.php' );
		self::assertStringContainsString( "add_action( 'admin_post_amsec_activity_recording'", $main );
		self::assertStringContainsString( "add_action( 'admin_post_amsec_uploads_rule'", $main );
	}
}
