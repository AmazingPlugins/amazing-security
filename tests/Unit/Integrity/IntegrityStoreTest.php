<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Integrity;

use AmazingPlugins\Security\Integrity\IntegrityCursor;
use AmazingPlugins\Security\Integrity\IntegrityStep;
use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Scan\ScanRun;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class IntegrityStoreTest extends TestCase {
	public function test_concurrent_start_and_partial_preserve_completed_report(): void {
		$options = new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { if ( isset( $this->values[ $key ] ) ) { return false; } $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { if ( ( $this->values[ $key ] ?? null ) === $value ) { return false; } $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
		};
		$store = new WordPressIntegrityStore( $options );
		$old = new ScanRun( new DateTimeImmutable( '-1 day' ), new DateTimeImmutable( '-1 day' ), array(), false );
		self::assertTrue( $store->begin( 'old', new IntegrityCursor( 'old' ) ) );
		$store->saveProgress( 'old', new IntegrityStep( new IntegrityCursor( 'old' ), true ) );
		$store->complete( 'old', $old );
		self::assertTrue( $store->begin( 'new', new IntegrityCursor( 'new' ) ) );
		self::assertFalse( $store->begin( 'other', new IntegrityCursor( 'other' ) ) );
		$cursor = new IntegrityCursor( 'new' );
		$cursor->partial = true;
		$store->saveProgress( 'new', new IntegrityStep( $cursor, true ) );
		$store->saveProgress( 'new', new IntegrityStep( $cursor, true ) );
		self::assertTrue( $store->latestProgress()->cursor->partial );
		self::assertSame( $old->finishedAt->format( 'c' ), $store->latestCompleted()->finishedAt->format( 'c' ) );
		self::assertTrue( $store->begin( 'unfinished', new IntegrityCursor( 'unfinished' ) ) );
		$active = json_decode( $options->values['amazing_security_integrity_active'], true );
		$active['expires'] = time() - 1;
		$options->values['amazing_security_integrity_active'] = json_encode( $active );
		self::assertTrue( $store->latestProgress()->finished );
		self::assertTrue( $store->begin( 'recovered', new IntegrityCursor( 'recovered' ) ) );
	}
}
