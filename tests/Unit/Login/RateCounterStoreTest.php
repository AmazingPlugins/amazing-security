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
			public function get_var( string $sql ): int { return str_contains( $sql, 'GET_LOCK' ) ? 1 : 0; }
			public function get_row( string $sql, string $mode ): ?array { return null; }
		};
		$store = new WordPressRateCounterStore( $db );
		self::assertFalse( $store->recordFailure( str_repeat( 'a', 64 ), 400 )->available );
		self::assertStringContainsString( 'ON DUPLICATE KEY UPDATE', $db->lastQuery );
	}

	public function test_summary_reports_unknown_when_counter_table_cannot_be_read(): void {
		$db = new class {
			public string $prefix = 'wp_';
			public string $last_error = 'table missing';
			public function prepare( string $query, mixed ...$args ): string { return $query; }
			public function query( string $sql ): bool { return false; }
			public function get_row( string $query, string $mode ): ?array { return null; }
		};
		self::assertSame( array( 'available' => false, 'observed' => 0, 'blocked' => 0 ), ( new WordPressRateCounterStore( $db ) )->summary( 1000 ) );
	}

	public function test_capacity_denies_new_address_and_reports_unknown_coverage(): void {
		$db = new class {
			public string $prefix = 'wp_';
			public string $last_error = '';
			public array $queries = array();
			public function prepare( string $sql, mixed ...$values ): string { return vsprintf( str_replace( array( '%s', '%d' ), array( "'%s'", '%d' ), $sql ), $values ); }
			public function query( string $sql ): int { $this->queries[] = $sql; return 1; }
			public function get_var( string $sql ): ?int {
				$this->queries[] = $sql;
				if ( str_contains( $sql, 'GET_LOCK' ) || str_contains( $sql, 'RELEASE_LOCK' ) ) { return 1; }
				if ( str_contains( $sql, 'COUNT(*)' ) ) { return 10000; }
				return null;
			}
			public function get_row( string $sql, string $mode ): ?array {
				return str_contains( $sql, 'AS observed' ) ? array( 'observed' => 10000, 'blocked' => 0 ) : null;
			}
		};
		$store = new WordPressRateCounterStore( $db );
		self::assertFalse( $store->recordFailure( str_repeat( 'a', 64 ), 100000 )->available );
		self::assertFalse( $store->summary( 100000 )['available'] );
		self::assertCount( 1, array_filter( $db->queries, fn( string $query ): bool => str_contains( $query, 'GET_LOCK' ) ) );
		self::assertCount( 1, array_filter( $db->queries, fn( string $query ): bool => str_contains( $query, 'RELEASE_LOCK' ) ) );
	}

	public function test_admission_locks_are_separate_for_databases_with_the_same_table_name(): void {
		$driver = static function ( string $database ): object {
			return new class( $database ) {
				public string $prefix = 'wp_';
				public string $last_error = '';
				public string $lock = '';
				public function __construct( public string $dbname ) {}
				public function prepare( string $sql, mixed ...$values ): string { return vsprintf( str_replace( array( '%s', '%d' ), array( "'%s'", '%d' ), $sql ), $values ); }
				public function query( string $sql ): int { return 1; }
				public function get_var( string $sql ): ?int {
					if ( str_contains( $sql, 'GET_LOCK' ) ) { $this->lock = $sql; return 1; }
					return str_contains( $sql, 'COUNT(*)' ) ? 0 : null;
				}
				public function get_row( string $sql, string $mode ): ?array { return null; }
			};
		};
		$first = $driver( 'wordpress_one' );
		$second = $driver( 'wordpress_two' );
		( new WordPressRateCounterStore( $first ) )->recordFailure( str_repeat( 'a', 64 ), 100000 );
		( new WordPressRateCounterStore( $second ) )->recordFailure( str_repeat( 'b', 64 ), 100000 );
		self::assertNotSame( '', $first->lock );
		self::assertNotSame( $first->lock, $second->lock );
	}
}
