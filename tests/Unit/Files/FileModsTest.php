<?php

declare(strict_types=1);

namespace {
	if ( ! function_exists( 'wp_is_file_mod_allowed' ) ) {
		function wp_is_file_mod_allowed( string $context ): bool { return $GLOBALS['amsec_file_mods'] ?? true; }
	}
	if ( ! function_exists( 'esc_html' ) ) {
		function esc_html( string $text ): string { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	}
}

namespace AmazingPlugins\Security\Tests\Unit\Files {
	use AmazingPlugins\Security\Files\FileMods;
	use PHPUnit\Framework\TestCase;

	final class FileModsTest extends TestCase {
		protected function tearDown(): void {
			unset( $GLOBALS['amsec_file_mods'] );
		}

		public function test_follows_the_site_file_mod_lock(): void {
			$GLOBALS['amsec_file_mods'] = true;
			self::assertTrue( FileMods::allowed() );
			$GLOBALS['amsec_file_mods'] = false;
			self::assertFalse( FileMods::allowed() );
			self::assertStringContainsString( 'DISALLOW_FILE_MODS', FileMods::denial() );
		}

		public function test_every_action_that_changes_files_checks_the_lock(): void {
			$root = dirname( __DIR__, 3 );
			self::assertStringContainsString( 'FileMods::requireAllowed()', (string) file_get_contents( $root . '/src/Admin/RepairAction.php' ) );
			self::assertStringContainsString( 'FileMods::requireAllowed()', (string) file_get_contents( $root . '/src/Free/Recovery/Module.php' ) );
		}

		public function test_core_and_theme_replace_and_chmod_are_not_shipped(): void {
			$root = dirname( __DIR__, 3 );
			self::assertFileDoesNotExist( $root . '/src/Free/Recovery/CoreFileRepair.php' );
			self::assertFileDoesNotExist( $root . '/src/Free/Recovery/DirectoryModes.php' );
			$module = (string) file_get_contents( $root . '/src/Free/Recovery/Module.php' );
			self::assertStringNotContainsString( 'amsec_recovery_repair', $module );
			self::assertStringNotContainsString( 'amsec_recovery_permission', $module );
		}
	}
}
