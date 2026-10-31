<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\AddressKey;
use AmazingPlugins\Security\Login\LoginSettings;
use AmazingPlugins\Security\Login\RateCounterStore;
use AmazingPlugins\Security\Login\RateLimiter;
use AmazingPlugins\Security\Login\RateState;
use PHPUnit\Framework\TestCase;

final class RateLimiterTest extends TestCase {
	public function test_forwarded_address_is_ignored_and_invalid_address_is_unknown(): void {
		$key = new AddressKey( str_repeat( 'k', 32 ) );
		self::assertSame(
			$key->fromServer( array( 'REMOTE_ADDR' => '2001:db8::1' ) ),
			$key->fromServer( array( 'REMOTE_ADDR' => '2001:db8::1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.10' ) )
		);
		self::assertNull( $key->fromServer( array( 'REMOTE_ADDR' => 'bad-ip' ) ) );
	}

	public function test_observe_never_blocks_but_block_mode_does(): void {
		$settings = $this->settings( 'observe' );
		$store = $this->store();
		$limiter = new RateLimiter( $settings, $store );
		for ( $i = 0; $i < 5; ++$i ) {
			$limiter->afterFailure( 'key', 100 );
		}
		self::assertFalse( $limiter->beforePassword( 'key', 101 )->blocked );
		$settings->mode = 'block';
		self::assertTrue( $limiter->beforePassword( 'key', 101 )->blocked );
		self::assertFalse( $limiter->beforePassword( 'key', 1001 )->blocked );
		self::assertFalse( $limiter->beforePassword( null, 101 )->blocked );
	}

	private function settings( string $mode ): LoginSettings {
		return new class( $mode ) implements LoginSettings {
			public function __construct( public string $mode ) {}
			public function rateMode(): string { return $this->mode; }
			public function setRateMode( string $mode ): void { $this->mode = $mode; }
			public function xmlRpcAuthDisabled(): bool { return false; }
			public function setXmlRpcAuthDisabled( bool $disabled ): void {}
			public function eraseOnUninstall(): bool { return false; }
			public function setEraseOnUninstall( bool $erase ): void {}
		};
	}

	private function store(): RateCounterStore {
		return new class implements RateCounterStore {
			public RateState $state;
			public function __construct() { $this->state = RateState::empty( 100 ); }
			public function state( string $addressKey, int $now ): RateState { return $this->state; }
			public function recordFailure( string $addressKey, int $now ): RateState { $this->state = $this->state->afterFailure( $now ); return $this->state; }
			public function clearExpired( int $now ): void {}
		};
	}
}
