<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

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
		$prior = $this->state( $addressKey, $now );
		if ( ! $prior->available ) {
			return $prior;
		}
		if ( 0 === $prior->failures ) {
			$this->clearExpired( $now );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Count caps short-lived counter rows.
			$count = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
			if ( $this->databaseFailed() || null === $count || (int) $count >= 10000 ) {
				return RateState::unavailable();
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
		return false === $written ? RateState::unavailable() : $this->state( $addressKey, $now );
	}

	public function clearExpired( int $now ): void {
		$cutoff = $now - 86400;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Expire no more than 250 old counter rows per write.
		$this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE updated_at < %d LIMIT 250", $cutoff ) );
	}

	private function databaseFailed(): bool {
		return isset( $this->db->last_error ) && '' !== $this->db->last_error;
	}
}
