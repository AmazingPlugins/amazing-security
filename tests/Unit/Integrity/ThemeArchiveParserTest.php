<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\ThemeArchiveParser;
use PHPUnit\Framework\TestCase;
use ZipArchive;

final class ThemeArchiveParserTest extends TestCase {
	private function archive( array $entries, bool $symlink = false ): string {
		$path = tempnam( sys_get_temp_dir(), 'amsec-zip-' );
		$zip = new ZipArchive();
		self::assertTrue( $zip->open( $path, ZipArchive::OVERWRITE ) );
		foreach ( $entries as $name => $body ) {
			$zip->addFromString( $name, $body );
			if ( $symlink ) {
				$zip->setExternalAttributesName( $name, ZipArchive::OPSYS_UNIX, 0120777 << 16 );
			}
		}
		$zip->close();
		$bytes = file_get_contents( $path );
		unlink( $path );
		return $bytes;
	}

	public function test_exact_theme_archive_becomes_sha256_manifest(): void {
		$result = ( new ThemeArchiveParser() )->parse( 'twentytwentyfive', '1.4', $this->archive( array( 'twentytwentyfive/style.css' => 'theme file' ) ), 'https://downloads.wordpress.org/theme/twentytwentyfive.1.4.zip' );
		self::assertNotNull( $result->manifest );
		self::assertSame( 'sha256', $result->manifest->algorithm );
		self::assertSame( array( hash( 'sha256', 'theme file' ) ), $result->manifest->files['style.css'] );
	}

	public function test_rejects_wrong_package_root_and_traversal(): void {
		$parser = new ThemeArchiveParser();
		foreach ( array( 'wrong/style.css', 'twentytwentyfive/../escape.php', '../outside.php' ) as $entry ) {
			$result = $parser->parse( 'twentytwentyfive', '1.4', $this->archive( array( $entry => 'x' ) ), 'https://downloads.wordpress.org/theme/twentytwentyfive.1.4.zip' );
			self::assertNull( $result->manifest, $entry );
		}
	}

	public function test_invalid_archive_returns_unknown_without_throwing(): void {
		$result = ( new ThemeArchiveParser() )->parse( 'theme', '1.0', 'not a zip', 'https://downloads.wordpress.org/theme/theme.1.0.zip' );
		self::assertNull( $result->manifest );
		self::assertSame( 'invalid_archive', $result->reason );
	}

	public function test_rejects_symlink_and_compression_bomb(): void {
		$parser = new ThemeArchiveParser();
		self::assertNull( $parser->parse( 'theme', '1.0', $this->archive( array( 'theme/link.php' => 'outside' ), true ), 'https://downloads.wordpress.org/theme/theme.1.0.zip' )->manifest );
		self::assertNull( $parser->parse( 'theme', '1.0', $this->archive( array( 'theme/huge.php' => str_repeat( 'A', 200000 ) ) ), 'https://downloads.wordpress.org/theme/theme.1.0.zip' )->manifest );
	}

	public function test_rejects_case_colliding_names(): void {
		$bytes = $this->archive( array( 'theme/Loader.php' => 'first', 'theme/loader.php' => 'second' ) );
		self::assertNull( ( new ThemeArchiveParser() )->parse( 'theme', '1.0', $bytes, 'https://downloads.wordpress.org/theme/theme.1.0.zip' )->manifest );
	}

	public function test_rejects_more_than_ten_thousand_entries(): void {
		$path = tempnam( sys_get_temp_dir(), 'amsec-many-' );
		$zip = new ZipArchive();
		self::assertTrue( $zip->open( $path, ZipArchive::OVERWRITE ) );
		for ( $i = 0; $i <= 10000; ++$i ) {
			$zip->addFromString( 'theme/file-' . $i . '.txt', '' );
		}
		$zip->close();
		$bytes = file_get_contents( $path );
		unlink( $path );
		self::assertNull( ( new ThemeArchiveParser() )->parse( 'theme', '1.0', $bytes, 'https://downloads.wordpress.org/theme/theme.1.0.zip' )->manifest );
	}

	public function test_rejects_more_than_sixty_four_megabytes_expanded(): void {
		$path = tempnam( sys_get_temp_dir(), 'amsec-expanded-' );
		$zip = new ZipArchive();
		self::assertTrue( $zip->open( $path, ZipArchive::OVERWRITE ) );
		$body = str_repeat( random_bytes( 10000 ), 50 );
		for ( $i = 0; $i < 140; ++$i ) {
			$zip->addFromString( 'theme/file-' . $i . '.php', $body );
		}
		$zip->close();
		$bytes = file_get_contents( $path );
		unlink( $path );
		$result = ( new ThemeArchiveParser() )->parse( 'theme', '1.0', $bytes, 'https://downloads.wordpress.org/theme/theme.1.0.zip' );
		self::assertSame( 'oversized_archive', $result->reason );
	}
}
