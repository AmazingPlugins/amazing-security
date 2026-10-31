<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\LoginSettings;
use AmazingPlugins\Security\Login\XmlRpcPolicy;
use PHPUnit\Framework\TestCase;

final class XmlRpcPolicyTest extends TestCase {
	public function test_authenticated_methods_can_be_disabled_without_changing_other_methods(): void {
		$settings = new class implements LoginSettings {
			public bool $disabled = false;
			public function rateMode(): string { return 'off'; }
			public function setRateMode( string $mode ): void {}
			public function xmlRpcAuthDisabled(): bool { return $this->disabled; }
			public function setXmlRpcAuthDisabled( bool $disabled ): void { $this->disabled = $disabled; }
			public function eraseOnUninstall(): bool { return false; }
			public function setEraseOnUninstall( bool $erase ): void {}
		};
		$policy = new XmlRpcPolicy( $settings );
		self::assertTrue( $policy->enabled( true ) );
		$settings->disabled = true;
		self::assertFalse( $policy->enabled( true ) );
		self::assertFalse( $policy->enabled( false ) );
	}
}
