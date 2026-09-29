<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Repair;

use AmazingPlugins\Security\Integrity\ChecksumManifestProvider;
use AmazingPlugins\Security\Integrity\HttpClient;
use AmazingPlugins\Security\Integrity\HttpResult;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Integrity\ManifestResult;
use AmazingPlugins\Security\Repair\PluginRepairSource;
use AmazingPlugins\Security\Repair\RepairCandidate;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use ZipArchive;

final class PluginRepairSourceTest extends TestCase {
	public function test_uses_exact_archive_entry_only_when_manifest_digest_matches(): void {
		if ( ! class_exists( ZipArchive::class ) ) {
			self::markTestSkipped( 'ZipArchive unavailable.' );
		}
		$source = new PluginRepairSource( $this->provider( md5( 'clean' ) ), $this->http( $this->zip( 'clean' ) ) );
		$bytes = $source->fetch( $this->candidate() );
		self::assertNotNull( $bytes );
		self::assertSame( 'clean', $bytes->contents );
		self::assertSame( hash( 'sha256', 'clean' ), $bytes->sha256 );
		self::assertNull( ( new PluginRepairSource( $this->provider( md5( 'other' ) ), $this->http( $this->zip( 'clean' ) ) ) )->fetch( $this->candidate() ) );
	}

	private function candidate(): RepairCandidate {
		$now = new DateTimeImmutable();
		$finding = new CheckResult( 'integrity-file', 'warn', 'Different.', 'https://wordpress.org/', $now, 'high', 'complete', array( 'package_type' => 'plugin', 'package' => 'hello-dolly:1.7.2', 'path' => 'hello.php', 'reason' => 'ok', 'observed_sha256' => str_repeat( 'b', 64 ) ), str_repeat( 'a', 32 ) );
		return RepairCandidate::fromReport( new ScanRun( $now, $now, array( $finding ), false ), str_repeat( 'a', 32 ) );
	}

	private function provider( string $digest ): ChecksumManifestProvider {
		return new class( $digest ) implements ChecksumManifestProvider {
			public function __construct( private readonly string $digest ) {}
			public function core( string $version, string $locale ): ManifestResult { return new ManifestResult( null, 'unsupported' ); }
			public function plugin( string $slug, string $version ): ManifestResult {
				return new ManifestResult( new Manifest( 'plugin', $slug . ':' . $version, 'https://downloads.wordpress.org/plugin-checksums/hello-dolly/1.7.2.json', new DateTimeImmutable(), 'md5', array( 'hello.php' => array( $this->digest ) ) ) );
			}
		};
	}

	private function http( string $zip ): HttpClient {
		return new class( $zip ) implements HttpClient {
			public function __construct( private readonly string $zip ) {}
			public function get( string $url, int $maxBytes ): HttpResult { return new HttpResult( 200, $this->zip ); }
		};
	}

	private function zip( string $contents ): string {
		$path = tempnam( sys_get_temp_dir(), 'amsec-repair-zip-' );
		$zip = new ZipArchive();
		$zip->open( $path, ZipArchive::OVERWRITE );
		$zip->addFromString( 'hello-dolly/hello.php', $contents );
		$zip->close();
		$bytes = file_get_contents( $path );
		unlink( $path );
		return $bytes;
	}
}
