<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\ChecksumManifestProvider;
use AmazingPlugins\Security\Integrity\Manifest;
use AmazingPlugins\Security\Integrity\ManifestResult;
use AmazingPlugins\Security\Integrity\TargetDiscovery;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class TargetDiscoveryTest extends TestCase {
	public function test_uses_installed_package_locale_and_skips_premium_origin(): void {
		$provider = new class implements ChecksumManifestProvider {
			public array $calls = array();
			public function core( string $version, string $locale ): ManifestResult {
				$this->calls[] = $locale;
				return new ManifestResult( new Manifest( 'core', "$version:$locale", 'https://api.wordpress.org/', new DateTimeImmutable(), 'md5', array( 'index.php' => array( str_repeat( 'a', 32 ) ) ) ) );
			}
			public function plugin( string $slug, string $version ): ManifestResult { $this->calls[] = $slug; return new ManifestResult( null, 'unavailable' ); }
		};
		$result = ( new TargetDiscovery( $provider ) )->discover( '6.6', 'de_DE', '/tmp', array( array( 'slug' => 'premium', 'version' => '1.0', 'root' => '/tmp', 'update_uri' => 'https://vendor.example/' ), array( 'slug' => 'single-file', 'version' => '1.0', 'root' => '/tmp', 'update_uri' => 'unsupported_local_path' ) ) );
		self::assertSame( array( 'de_DE' ), $provider->calls );
		self::assertCount( 1, $result->targets );
		self::assertCount( 2, $result->findings );
		self::assertSame( 'unsupported_local_path', $result->findings[1]->evidence['reason'] );
	}

	public function test_manifest_change_alters_resume_signature(): void {
		$provider = new class implements ChecksumManifestProvider {
			public string $digest = '';
			public function core( string $version, string $locale ): ManifestResult { return new ManifestResult( new Manifest( 'core', "$version:$locale", 'https://api.wordpress.org/', new DateTimeImmutable(), 'md5', array( 'index.php' => array( $this->digest ) ) ) ); }
			public function plugin( string $slug, string $version ): ManifestResult { return new ManifestResult( null, 'unavailable' ); }
		};
		$discovery = new TargetDiscovery( $provider );
		$provider->digest = str_repeat( 'a', 32 );
		$first = $discovery->discover( '6.6', 'en_US', '/tmp', array() );
		$provider->digest = str_repeat( 'b', 32 );
		$second = $discovery->discover( '6.6', 'en_US', '/tmp', array() );
		self::assertNotSame( $first->signature, $second->signature );
	}
}
