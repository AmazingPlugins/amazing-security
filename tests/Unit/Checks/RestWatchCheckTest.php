<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Checks;

use AmazingPlugins\Security\Checks\RestWatchCheck;
use AmazingPlugins\Security\Findings\State;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class RestWatchCheckTest extends TestCase {
	public function test_observe_is_success(): void {
		$result = ( new RestWatchCheck( static fn (): bool => false ) )->run( new ScanContext() )[0];
		self::assertSame( State::PASS, $result->state );
		self::assertSame( 'observe', $result->evidence['status'] );
		self::assertSame( 6, $result->evidence['rule_count'] );
		self::assertSame( '2026.10.07.3', $result->evidence['pack'] );
		self::assertStringContainsString( 'observe only', $result->summary );
		self::assertStringContainsString( '6 public REST rules', $result->summary );
	}

	public function test_disabled_constant_is_warning(): void {
		$result = ( new RestWatchCheck( static fn (): bool => true ) )->run( new ScanContext() )[0];
		self::assertSame( State::WARN, $result->state );
		self::assertSame( 'disabled', $result->evidence['status'] );
		self::assertStringContainsString( 'AMSEC_DISABLE_FIREWALL', $result->summary );
		self::assertStringContainsString( '6 observe rules', $result->summary );
	}
}
