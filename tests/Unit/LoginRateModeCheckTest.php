<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Checks\LoginRateModeCheck;
use AmazingPlugins\Security\Checks\Values;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class LoginRateModeCheckTest extends TestCase {
	public function test_mode_states_and_source_are_explicit(): void {
		foreach ( array( array( null, 'warn', 'off' ), array( 'off', 'warn', 'off' ), array( 'observe', 'warn', 'observe' ), array( 'block', 'pass', 'block' ), array( 'broken', 'unknown', 'unavailable' ), array( 8, 'unknown', 'unavailable' ) ) as list( $mode, $state, $evidence ) ) {
			$result = ( new LoginRateModeCheck( static fn(): mixed => $mode ) )->run( new ScanContext() )[0];
			self::assertSame( 'login-rate-mode', $result->checkId );
			self::assertSame( $state, $result->state );
			self::assertSame( $evidence, $result->evidence['mode'] );
			self::assertSame( 'https://developer.wordpress.org/advanced-administration/security/brute-force/', $result->sourceUrl );
		}
	}

	public function test_hardening_composition_has_six_unique_checks(): void {
		$values = new class() implements Values {
			public function coreUpdateAvailable(): ?bool {
				return false; }
			public function debugDisplayed(): ?bool {
				return false; }
			public function fileEditorDisabled(): ?bool {
				return true; }
			public function fileEditorFix(): string {
				return 'config-on'; }
			public function debugHiddenByPlugin(): bool {
				return false; }
			public function adminUsesHttps(): ?bool {
				return true; }
			public function hasDefaultAdminLogin(): ?bool {
				return false; }
		};
		$checks = LocalHardeningScanService::checks( $values, static fn(): mixed => 'off' );
		self::assertSame( array( 'https-admin', 'core-updates', 'default-admin-login', 'debug-display', 'file-editor', 'login-rate-mode' ), array_map( static fn( $check ): string => $check->id(), $checks ) );
	}
}
