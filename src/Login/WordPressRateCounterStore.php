<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class WordPressRateCounterStore implements RateCounterStore {
	private string $table;

	public function __construct( private object $db ) {
		$this->table = $db->prefix . 'amsec_login_rate';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table = $wpdb->prefix . 'amsec_login_rate';
		$sql   = "CREATE TABLE {$table} (
			address_key char(64) NOT NULL,
			failures smallint unsigned NOT NULL DEFAULT 0,
			window_started_at bigint unsigned NOT NULL DEFAULT 0,
			blocked_until bigint unsigned NOT NULL DEFAULT 0,
			updated_at bigint unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (address_key),
			KEY updated_at (updated_at)
		) {$wpdb->get_charset_collate()};";
		dbDelta( $sql );
		update_option( 'amsec_login_schema_version', '1', false );
		self::ensureScheduled();
	}

	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'amsec_login_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_login_cleanup' );
		}
	}

	public function state( string $addressKey, int $now ): RateState {
		if ( ! preg_match( '/\A[a-f0-9]{64}\z/', $addressKey ) ) {
			return RateState::unavailable();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- A bounded per-address counter must be read outside the options cache.
		$row = $this->db->get_row( $this->db->prepare( "SELECT failures, window_started_at, blocked_until FROM {$this->table} WHERE address_key = %s", $addressKey ), 'ARRAY_A' );
		if ( null === $row ) {
			return $this->databaseFailed() ? RateState::unavailable() : RateState::empty( $now );
		}
		$state = new RateState( (int) $row['failures'], (int) $row['window_started_at'], (int) $row['blocked_until'] );
		return $now >= $state->windowStartedAt + 900 && ! $state->isBlocked( $now ) ? RateState::empty( $now ) : $state;
	}

	public function recordFailure( string $addressKey, int $now ): RateState {
		$this->clearExpired( $now );
		$prior = $this->state( $addressKey, $now );
		if ( ! $prior->available ) {
			return $prior;
		}
		$locked = false;
		if ( 0 === $prior->failures ) {
			$database = (string) ( $this->db->dbname ?? ( defined( 'DB_NAME' ) ? DB_NAME : '' ) );
			$lockName = 'amsec_rate_' . substr( hash( 'sha256', $database . ':' . $this->table ), 0, 32 );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Serialize admission of new counter keys at the capacity boundary.
			$locked = 1 === (int) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s, 0)', $lockName ) );
			if ( ! $locked || $this->databaseFailed() ) {
				$this->markUnavailable();
				return RateState::unavailable();
			}
		}
		try {
			if ( $locked ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Existing keys may still update when the table is full.
				$exists = $this->db->get_var( $this->db->prepare( "SELECT 1 FROM {$this->table} WHERE address_key = %s", $addressKey ) );
				if ( $this->databaseFailed() ) {
					$this->markUnavailable();
					return RateState::unavailable();
				}
				if ( null === $exists ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Advisory lock keeps the count and insert in one admission section.
					$count = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
					if ( $this->databaseFailed() || null === $count || (int) $count >= 10000 ) {
						$this->markUnavailable();
						return RateState::unavailable();
					}
				}
			}
			$cutoff = $now - 900;
			$sql    = "INSERT INTO {$this->table} (address_key, failures, window_started_at, blocked_until, updated_at)
			VALUES (%s, 1, %d, 0, %d)
			ON DUPLICATE KEY UPDATE
			failures = IF(blocked_until > %d, failures, IF(window_started_at <= %d, 1, LEAST(failures + 1, 5))),
			blocked_until = IF(blocked_until > %d, blocked_until, IF(window_started_at <= %d, 0, IF(failures >= 5, %d, 0))),
			window_started_at = IF(window_started_at <= %d, %d, window_started_at),
			updated_at = %d";
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Atomic upsert avoids lost concurrent failures.
			$written = $this->db->query( $this->db->prepare( $sql, $addressKey, $now, $now, $now, $cutoff, $now, $cutoff, $now + 900, $cutoff, $now, $now ) );
			if ( false === $written ) {
				$this->markUnavailable();
				return RateState::unavailable();
			}
			return $this->state( $addressKey, $now );
		} finally {
			if ( $locked ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Release the per-site admission lock on every path.
				$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lockName ) );
			}
		}
	}

	public function clearExpired( int $now ): void {
		$cutoff = $now - 86400;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- The table holds at most 10,000 keys; an indexed delete drains all expired keys.
		if ( false === $this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE updated_at < %d LIMIT 10000", $cutoff ) ) ) {
			$this->markUnavailable();
		}
	}

	public function purge(): void {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- An owner turning protection off discards all address counters.
		$deleted = $this->db->query( "DELETE FROM {$this->table}" );
		if ( false === $deleted ) {
			$this->markUnavailable();
		} elseif ( function_exists( 'delete_transient' ) ) {
			delete_transient( 'amsec_login_counter_fault' );
		}
	}

	public function summary( int $now ): array {
		$this->clearExpired( $now );
		$cutoff = $now - 86400;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Aggregate counts only; no address keys leave storage.
		$row = $this->db->get_row( $this->db->prepare( "SELECT COUNT(*) AS observed, COALESCE(SUM(IF(blocked_until > %d, 1, 0)), 0) AS blocked FROM {$this->table} WHERE updated_at >= %d", $now, $cutoff ), 'ARRAY_A' );
		if ( ! is_array( $row ) || $this->databaseFailed() || (int) ( $row['observed'] ?? 0 ) >= 10000 || ( function_exists( 'get_transient' ) && get_transient( 'amsec_login_counter_fault' ) ) ) {
			return array(
				'available' => false,
				'observed'  => 0,
				'blocked'   => 0,
			);
		}
		return array(
			'available' => true,
			'observed'  => (int) ( $row['observed'] ?? 0 ),
			'blocked'   => (int) ( $row['blocked'] ?? 0 ),
		);
	}

	private function databaseFailed(): bool {
		return isset( $this->db->last_error ) && '' !== $this->db->last_error;
	}

	private function markUnavailable(): void {
		if ( function_exists( 'set_transient' ) ) {
			set_transient( 'amsec_login_counter_fault', '1', 15 * MINUTE_IN_SECONDS );
		}
	}
}
