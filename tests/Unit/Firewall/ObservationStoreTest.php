<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\ObservationStore;
use AmazingPlugins\Security\Integrity\OptionGateway;
use PHPUnit\Framework\TestCase;

final class ObservationStoreTest extends TestCase {
	public function test_records_only_bounded_rule_counts_and_time(): void {
		$options = $this->options();
		$store   = new ObservationStore( $options );
		self::assertTrue( $store->record( array( 'AS-REST-001' ), 1000 ) );
		self::assertTrue( $store->record( array( 'AS-REST-001', 'AS-REST-002' ), 1001 ) );
		self::assertSame( 2, $store->summary()['AS-REST-001']['count'] );
		self::assertSame( 1001, $store->summary()['AS-REST-001']['last_at'] );
		self::assertSame( 1, $store->summary()['AS-REST-002']['count'] );
		self::assertStringNotContainsString( 'password', json_encode( $options->values ) );
	}

	public function test_rejects_unknown_rule_id_without_writing(): void {
		$options = $this->options();
		$store   = new ObservationStore( $options );
		self::assertFalse( $store->record( array( 'not-a-rule' ), 1000 ) );
		self::assertSame( array(), $options->values );
	}

	private function options(): OptionGateway {
		return new class() implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed {
				return $this->values[ $key ] ?? null; }
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
	}
}
