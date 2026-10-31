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
		self::assertSame( 'uploads', $targets[0]->kind );
		self::assertSame( $manifest, $targets[1]->manifest );
		self::assertNull( $targets[2]->manifest );
	}

	public function test_single_file_plugin_is_a_bounded_local_target(): void {
		$discovery = new DiscoveryResult( array(), array(), 'signature', true );
		$targets = ( new FileScanPlanBuilder() )->build( $discovery, array( array( 'slug' => 'hello.php', 'version' => '1.0', 'root' => '/tmp/plugins', 'update_uri' => 'unsupported_local_path', 'single_file' => 'hello.php' ) ), array(), '/tmp/uploads' );
		self::assertSame( 'hello.php', $targets[1]->singleFile );
		self::assertSame( '/tmp/plugins', $targets[1]->root );
		self::assertNull( $targets[1]->manifest );
	}

	public function test_core_inventory_runs_after_uploads_and_extensions(): void {
		$core = new Manifest( 'core', '6.6:en_US', 'https://wordpress.org/', new DateTimeImmutable(), 'sha256', array() );
		$discovery = new DiscoveryResult( array( new IntegrityTarget( $core, '/tmp/core' ) ), array(), 'signature', false );
		$targets = ( new FileScanPlanBuilder() )->build( $discovery, array( array( 'slug' => 'demo', 'version' => '1.0', 'root' => '/tmp/demo' ) ), array(), '/tmp/uploads' );
		self::assertSame( array( 'uploads', 'plugin', 'core' ), array_column( $targets, 'kind' ) );
	}

	public function test_nonrepository_folder_plugin_still_gets_a_local_content_target(): void {
		$discovery = new DiscoveryResult( array(), array(), 'signature', true );
		$targets = ( new FileScanPlanBuilder() )->build( $discovery, array( array( 'slug' => 'my_plugin', 'version' => '1.0', 'root' => '/tmp/plugins/my_plugin', 'update_uri' => 'unsupported_local_path', 'local_only' => true ) ), array(), '/tmp/uploads' );
		self::assertCount( 2, $targets );
		self::assertSame( '/tmp/plugins/my_plugin', $targets[1]->root );
		self::assertNull( $targets[1]->singleFile );
	}
}
