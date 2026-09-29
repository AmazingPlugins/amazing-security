<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Mcp\AbilityRegistrar;
use AmazingPlugins\Security\Mcp\FindingsGateway;
use AmazingPlugins\Security\Mcp\McpPreferences;
use AmazingPlugins\Security\Mcp\ScanGateway;
use PHPUnit\Framework\TestCase;

final class McpAbilityRegistrarTest extends TestCase {
	public function test_registers_only_six_explicit_mcp_abilities_and_rechecks_access(): void {
		$options = new class implements OptionGateway {
			public array $values = array();
			public function get( string $key ): mixed { return $this->values[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->values[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->values[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { return false; }
			public function deleteIfSame( string $key, string $expected ): bool { return false; }
		};
		$prefs = new McpPreferences( $options );
		$admin = true;
		$registrar = new AbilityRegistrar( $prefs, new FindingsGateway(), new ScanGateway( $options ), static function () use ( &$admin ): bool { return $admin; }, static fn(): int => 7 );
		self::assertFalse( $registrar->allowed() );
		self::assertSame( 'forbidden', $registrar->execute( 'list-findings', array() )['state'] );
		$prefs->setEnabled( true );
		self::assertTrue( $registrar->allowed() );
		$definitions = $registrar->definitions();
		self::assertSame( array( 'amazing-security/list-findings', 'amazing-security/get-finding', 'amazing-security/start-scan', 'amazing-security/get-scan', 'amazing-security/propose-fix', 'amazing-security/get-fix-status' ), array_keys( $definitions ) );
		self::assertFalse( $definitions['amazing-security/propose-fix']['input_schema']['additionalProperties'] );
		foreach ( $definitions as $definition ) {
			self::assertTrue( $definition['meta']['mcp']['public'] );
			self::assertArrayNotHasKey( 'public', $definition['meta'] );
			self::assertFalse( $definition['input_schema']['additionalProperties'] );
		}
		$admin = false;
		self::assertFalse( $registrar->allowed() );
		self::assertSame( 'forbidden', $registrar->execute( 'list-findings', array() )['state'] );
		$admin = true;
		$prefs->setEnabled( false );
		self::assertSame( 'forbidden', $registrar->execute( 'list-findings', array() )['state'] );
	}

	public function test_rejects_unknown_scan_type_and_unbounded_list_input(): void {
		$options = new class implements OptionGateway {
			public function get( string $key ): mixed { return '1'; }
			public function add( string $key, string $value ): bool { return true; }
			public function set( string $key, string $value ): bool { return true; }
			public function delete( string $key ): void {}
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { return false; }
			public function deleteIfSame( string $key, string $expected ): bool { return false; }
		};
		$registrar = new AbilityRegistrar( new McpPreferences( $options ), new FindingsGateway(), new ScanGateway( $options ), static fn(): bool => true, static fn(): int => 7 );
		self::assertSame( 'invalid_input', $registrar->execute( 'list-findings', array( 'limit' => 1000 ) )['state'] );
		self::assertSame( 'invalid_input', $registrar->execute( 'start-scan', array( 'type' => 'file' ) )['state'] );
		self::assertSame( 'invalid_input', $registrar->execute( 'get-scan', array( 'scan_id' => 'bad' ) )['state'] );
	}
}
