<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Login\RateState;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;
use PHPUnit\Framework\TestCase;

final class RateCounterStoreTest extends TestCase {
	public function test_fifth_failure_blocks_until_fifteen_minutes_later(): void {
		$state = RateState::empty( 400 );
		for ( $attempt = 0; $attempt < 5; ++$attempt ) {
			$state = $state->afterFailure( 400 );
		}
		self::assertSame( 5, $state->failures );
		self::assertSame( 1300, $state->blockedUntil );
		self::assertSame( 1, $state->afterFailure( 1301 )->failures );
	}

	public function test_unavailable_state_never_blocks(): void {
		self::assertFalse( RateState::unavailable()->isBlocked( 500 ) );
	}

	public function test_database_write_failure_fails_open_and_uses_atomic_upsert(): void {
		$db = new class {
			public string $prefix = 'wp_';
			public string $lastQuery = '';
			public function prepare( string $sql, mixed ...$values ): string { return vsprintf( str_replace( array( '%s', '%d' ), array( "'%s'", '%d' ), $sql ), $values ); }
			public function query( string $sql ): bool { $this->lastQuery = $sql; return false; }
			public function get_var( string $sql ): int { return 0; }
			public function get_row( string $sql, string $mode ): ?array { return null; }
		};
		$store = new WordPressRateCounterStore( $db );
		self::assertFalse( $store->recordFailure( str_repeat( 'a', 64 ), 400 )->available );
		self::assertStringContainsString( 'ON DUPLICATE KEY UPDATE', $db->lastQuery );
	}
}
