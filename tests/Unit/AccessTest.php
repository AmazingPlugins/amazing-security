<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Access;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class AccessTest extends TestCase {
	public function test_sessions_are_for_an_administrator_or_the_owner(): void {
		self::assertTrue( Access::session( true, 2, 5 ) );
		self::assertTrue( Access::session( false, 5, 5 ) );
		self::assertFalse( Access::session( false, 2, 5 ) );
		self::assertFalse( Access::session( true, 0, 5 ) );
	}

	public function test_sign_in_secrets_stay_on_the_signed_in_account(): void {
		self::assertTrue( Access::ownSecret( 5, 5 ) );
		self::assertFalse( Access::ownSecret( 2, 5 ) );
		self::assertFalse( Access::ownSecret( 0, 5 ) );
	}

	public function test_another_account_needs_an_administrator_and_cannot_be_yourself(): void {
		self::assertTrue( Access::otherAccount( true, 2, 5 ) );
		self::assertFalse( Access::otherAccount( true, 5, 5 ) );
		self::assertFalse( Access::otherAccount( false, 2, 5 ) );
	}

	public function test_site_screens_ask_for_an_administrator(): void {
		$src   = dirname( __DIR__, 2 ) . '/src';
		$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $src ) );
		$seen  = 0;
		foreach ( $files as $file ) {
			if ( ! $file->isFile() || 'php' !== $file->getExtension() ) {
				continue;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local plugin source, not a remote URL.
			$text = (string) file_get_contents( $file->getPathname() );
			if ( ! str_contains( $text, 'add_submenu_page' ) ) {
				continue;
			}
			++$seen;
			if ( 'SessionPage.php' === $file->getFilename() ) {
				self::assertStringContainsString( "'read'", $text );
				continue;
			}
			self::assertStringContainsString( "'manage_options'", $text, $file->getFilename() );
			self::assertStringNotContainsString( ", 'read',", $text, $file->getFilename() );
		}
		self::assertGreaterThan( 10, $seen );
	}
}
