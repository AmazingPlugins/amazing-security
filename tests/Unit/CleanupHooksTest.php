<?php
namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Lifecycle\Cleanup;
use PHPUnit\Framework\TestCase;

final class CleanupHooksTest extends TestCase {
	/** Every event the plugin schedules must be cleared on deactivation and uninstall. */
	public function test_cleanup_clears_every_scheduled_hook(): void {
		$root  = dirname( __DIR__, 2 );
		$found = array();
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . '/src', \FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			if ( 'php' === $file->getExtension() && 1 === preg_match_all( "/wp_schedule_(?:single_)?event\([^;]*?'(amsec_[a-z_]+)'/", (string) file_get_contents( $file->getPathname() ), $match ) ) {
				$found = array_merge( $found, $match[1] );
			}
		}
		preg_match_all( "/wp_schedule_(?:single_)?event\([^;]*?'(amsec_[a-z_]+)'/", (string) file_get_contents( $root . '/amazing-security.php' ), $main );
		$found = array_unique( array_merge( $found, $main[1] ) );
		self::assertNotEmpty( $found );
		self::assertSame( array(), array_values( array_diff( $found, Cleanup::CRON_HOOKS ) ) );
	}

	public function test_uninstall_runs_the_shared_cleanup_before_the_erase_choice(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/uninstall.php' );
		self::assertLessThan( strpos( $source, 'amsec_login_erase_on_uninstall' ), strpos( $source, 'Cleanup::removeHotlinkBlock' ) );
		self::assertStringContainsString( 'Cleanup::eraseAllData', $source );
	}
}
