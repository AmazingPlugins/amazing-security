<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WorkerLock;
use PHPUnit\Framework\TestCase;

final class WorkerLockTest extends TestCase {
	public function test_acquire_and_release_do_not_remove_a_newer_lock(): void {
		$options = new class() implements OptionGateway {
			public array $values         = array();
			public ?string $replaceOnGet = null;
			public function get( string $key ): mixed {
				$old = $this->values[ $key ] ?? null;
				if ( null !== $this->replaceOnGet ) {
					$this->values[ $key ] = $this->replaceOnGet;
					$this->replaceOnGet   = null;
				} return $old; }
			public function add( string $key, string $value ): bool {
				if ( isset( $this->values[ $key ] ) ) {
					return false;
				} $this->values[ $key ] = $value;
				return true; }
			public function set( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
				return true; }
			public function delete( string $key ): void {
				unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} $this->values[ $key ] = $replacement;
				return true; }
			public function deleteIfSame( string $key, string $expected ): bool {
				if ( ( $this->values[ $key ] ?? null ) !== $expected ) {
					return false;
				} unset( $this->values[ $key ] );
				return true; }
		};
		$lock    = new WorkerLock( $options );
		self::assertTrue( $lock->acquire( 'scan-1' ) );
		$fileLock = new WorkerLock( $options, 'amsec_security_scanner_file_scan_worker_lock' );
		self::assertTrue( $fileLock->acquire( 'file-scan-1' ) );
		$fileLock->release();
		self::assertFalse( ( new WorkerLock( $options ) )->acquire( 'scan-2' ) );
		$lock->release();
		self::assertTrue( ( new WorkerLock( $options ) )->acquire( 'scan-2' ) );
		$key                     = 'amsec_security_scanner_integrity_worker_lock';
		$options->values[ $key ] = json_encode(
			array(
				'scan_id' => 'stale',
				'expires' => time() - 1,
			)
		);
		$new                     = json_encode(
			array(
				'scan_id' => 'new',
				'expires' => time() + 60,
			)
		);
		$options->replaceOnGet   = $new;
		self::assertFalse( ( new WorkerLock( $options ) )->acquire( 'scan-3' ) );
		self::assertSame( $new, $options->values[ $key ] );
	}
}
