<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\ObservationStore;
use AmazingPlugins\Security\Firewall\RequestInspector;
use AmazingPlugins\Security\Firewall\RestFirewall;
use AmazingPlugins\Security\Integrity\OptionGateway;
use PHPUnit\Framework\TestCase;

final class RestFirewallTest extends TestCase {
	public function test_observe_records_rule_only_and_never_blocks(): void {
		$options  = new class() implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed {
				return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool {
				$this->values[ $key ] = $value;
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
				return false; }
		};
		$store    = new ObservationStore( $options );
		$firewall = new RestFirewall( new RequestInspector(), $store );
		$result   = $firewall->observe( array( 'path' => '../private/secret' ), false, 1000 );
		self::assertSame( 'observe', $result['state'] );
		self::assertSame( 1, $store->summary()['AS-REST-001']['count'] );
		self::assertStringNotContainsString( '../private/secret', json_encode( $options->values ) );
		self::assertSame( 'skip', $firewall->observe( array( 'path' => '../private/secret' ), true, 1001 )['state'] );
		self::assertSame( 1, $store->summary()['AS-REST-001']['count'] );
		$body = $firewall->observe( array(), false, 1002, array( 'note' => '%252e%252e%252fsecret' ) );
		self::assertSame( 'observe', $body['state'] );
		self::assertSame( 2, $store->summary()['AS-REST-001']['count'] );
		self::assertSame( array(), $firewall->observe( array(), false, 1003, array( 'password' => '../private/secret' ) )['rules'] );
		self::assertSame( 2, $store->summary()['AS-REST-001']['count'] );
		self::assertStringNotContainsString( '../private/secret', json_encode( $options->values ) );
		self::assertStringNotContainsString( '%252e', json_encode( $options->values ) );
	}
}
