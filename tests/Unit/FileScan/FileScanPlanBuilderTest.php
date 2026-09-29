<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\FileScan;

use AmazingPlugins\Security\FileScan\FileScanPlanBuilder;
use AmazingPlugins\Security\Integrity\DiscoveryResult;
use AmazingPlugins\Security\Integrity\IntegrityTarget;
use AmazingPlugins\Security\Integrity\Manifest;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class FileScanPlanBuilderTest extends TestCase {
	public function test_keeps_unverified_and_missing_packages_visible_to_local_scanner(): void {
		$manifest = new Manifest( 'plugin', 'repo:1.0', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array( 'a.php' => array( str_repeat( 'a', 64 ) ) ) );
		$discovery = new DiscoveryResult( array( new IntegrityTarget( $manifest, '/tmp/repo' ) ), array(), 'signature', false );
		$targets = ( new FileScanPlanBuilder() )->build( $discovery, array( array( 'slug' => 'repo', 'version' => '1.0', 'root' => '/tmp/repo' ), array( 'slug' => 'custom', 'version' => '1.0', 'root' => '/tmp/not-there' ) ), array(), '/tmp/uploads' );
		self::assertCount( 3, $targets );
		self::assertSame( $manifest, $targets[0]->manifest );
		self::assertNull( $targets[1]->manifest );
		self::assertSame( 'uploads', $targets[2]->kind );
	}
}
