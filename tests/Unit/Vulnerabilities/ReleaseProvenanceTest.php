<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Vulnerabilities\ReleaseProvenance;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class ReleaseProvenanceTest extends TestCase {
	private string $root;

	protected function setUp(): void {
		$this->root = sys_get_temp_dir() . '/amsec-provenance-' . bin2hex( random_bytes( 5 ) );
		mkdir( $this->root );
		file_put_contents( $this->root . '/main.php', '<?php echo 1;' );
	}

	protected function tearDown(): void {
		foreach ( glob( $this->root . '/*' ) ?: array() as $file ) {
			unlink( $file );
		}
		rmdir( $this->root );
	}

	public function test_exact_release_files_prove_identity(): void {
		self::assertTrue( ( new ReleaseProvenance() )->verify( $this->manifest(), $this->root ) );
	}

	public function test_modified_or_extra_executable_file_does_not_prove_identity(): void {
		file_put_contents( $this->root . '/main.php', '<?php echo 2;' );
		self::assertFalse( ( new ReleaseProvenance() )->verify( $this->manifest(), $this->root ) );
		file_put_contents( $this->root . '/main.php', '<?php echo 1;' );
		file_put_contents( $this->root . '/backdoor.php', '<?php echo 3;' );
		self::assertFalse( ( new ReleaseProvenance() )->verify( $this->manifest(), $this->root ) );
	}

	public function test_legacy_md5_manifest_does_not_prove_release_identity(): void {
		$manifest = new Manifest( 'plugin', 'akismet:5.6', 'https://downloads.wordpress.org/plugin-checksums/akismet/5.6.json', new DateTimeImmutable(), 'md5', array( 'main.php' => array( md5( '<?php echo 1;' ) ) ) );
		self::assertFalse( ( new ReleaseProvenance() )->verify( $manifest, $this->root ) );
	}

	public function test_file_state_changes_after_same_size_edit(): void {
		$proof  = new ReleaseProvenance();
		$before = $proof->fileState( $this->root );
		file_put_contents( $this->root . '/main.php', '<?php echo 2;' );
		self::assertNotNull( $before );
		self::assertNotSame( $before, $proof->fileState( $this->root ) );
	}

	private function manifest(): Manifest {
		return new Manifest( 'plugin', 'akismet:5.6', 'https://downloads.wordpress.org/plugin-checksums/akismet/5.6.json', new DateTimeImmutable(), 'sha256', array( 'main.php' => array( hash( 'sha256', '<?php echo 1;' ) ) ) );
	}
}
