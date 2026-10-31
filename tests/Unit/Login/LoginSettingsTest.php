<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Integrity\OptionGateway;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use PHPUnit\Framework\TestCase;

final class LoginSettingsTest extends TestCase {
	public function test_defaults_are_off_and_writes_are_validated(): void {
		$options = new class implements OptionGateway {
			public array $data = array();
			public function get( string $key ): mixed { return $this->data[ $key ] ?? null; }
			public function add( string $key, string $value ): bool { $this->data[ $key ] = $value; return true; }
			public function set( string $key, string $value ): bool { $this->data[ $key ] = $value; return true; }
			public function delete( string $key ): void { unset( $this->data[ $key ] ); }
			public function replaceIfSame( string $key, string $expected, string $replacement ): bool { return false; }
			public function deleteIfSame( string $key, string $expected ): bool { return false; }
		};
		$settings = new WordPressLoginSettings( $options );
		self::assertSame( 'off', $settings->rateMode() );
		self::assertFalse( $settings->xmlRpcAuthDisabled() );
		self::assertFalse( $settings->eraseOnUninstall() );
		$settings->setRateMode( 'observe' );
		self::assertSame( 'observe', $settings->rateMode() );
		$settings->setRateMode( 'block' );
		self::assertSame( 'block', $settings->rateMode() );
		$settings->setXmlRpcAuthDisabled( true );
		self::assertTrue( $settings->xmlRpcAuthDisabled() );
		$this->expectException( \InvalidArgumentException::class );
		$settings->setRateMode( 'unsafe' );
	}
}
