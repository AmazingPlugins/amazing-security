<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Checks;

use AmazingPlugins\Security\Checks\AuthFactorCheck;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Login\AuthFactorStatus;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class AuthFactorCheckTest extends TestCase {
	public function test_missing_is_critical_and_mentions_two_factor(): void {
		$check = new AuthFactorCheck(
			'authenticator-app',
			static fn (): array => array(
				'state'        => AuthFactorStatus::MISSING,
				'provider'     => '',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			)
		);
		$result = $check->run( new ScanContext() )[0];
		self::assertSame( State::CRITICAL, $result->state );
		self::assertSame( 'high', $result->confidence );
		self::assertStringContainsString( 'Two Factor', $result->summary );
		self::assertStringContainsString( 'does not enroll', $result->summary );
	}

	public function test_active_is_success(): void {
		$check = new AuthFactorCheck(
			'passkeys-status',
			static fn (): array => array(
				'state'        => AuthFactorStatus::ACTIVE,
				'provider'     => 'Two Factor',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			)
		);
		$result = $check->run( new ScanContext() )[0];
		self::assertSame( State::PASS, $result->state );
		self::assertStringContainsString( 'Two Factor', $result->summary );
	}

	public function test_available_is_warning(): void {
		$check = new AuthFactorCheck(
			'authenticator-app',
			static fn (): array => array(
				'state'        => AuthFactorStatus::AVAILABLE,
				'provider'     => 'Two Factor',
				'suggest_slug' => 'two-factor',
				'suggest_name' => 'Two Factor',
			)
		);
		$result = $check->run( new ScanContext() )[0];
		self::assertSame( State::WARN, $result->state );
	}
}
