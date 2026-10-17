<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

final class BotCounterStore {
	private string $table;

	public function __construct( private readonly object $db ) {
		$this->table = $db->prefix . 'amsec_bot_rate';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table = $wpdb->prefix . 'amsec_bot_rate';
		dbDelta(
			"CREATE TABLE {$table} (
			address_key char(64) NOT NULL,
			attempts smallint unsigned NOT NULL DEFAULT 0,
			window_started_at bigint unsigned NOT NULL DEFAULT 0,
			updated_at bigint unsigned NOT NULL DEFAULT 0,
			PRIMARY KEY  (address_key),
			KEY updated_at (updated_at)
		) ENGINE=InnoDB {$wpdb->get_charset_collate()};"
		);
		if ( self::schemaReady( $wpdb ) ) {
			update_option( 'amsec_bot_schema_version', '1', false );
		} else {
			delete_option( 'amsec_bot_schema_version' );
		}
		self::ensureScheduled();
	}

	public static function schemaReady( object $db ): bool {
		$prior = $db->suppress_errors( true );
		$table = $db->prefix . 'amsec_bot_rate';
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Verify required columns before marking installation complete.
			$result = $db->query( "SELECT address_key,attempts,window_started_at,updated_at FROM {$table} LIMIT 0" );
			return false !== $result && '' === $db->last_error;
		} catch ( \Throwable ) {
			return false;
		} finally {
			$db->suppress_errors( $prior );
		}
	}

	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'amsec_bot_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_bot_cleanup' );
		}
	}

	public function record( string $key, int $window, int $now ): ?int {
		if ( ! preg_match( '/^[a-f0-9]{64}$/D', $key ) || ! in_array( $window, array( 300, 900 ), true ) || $now < 1 ) {
			return null;
		}
		$priorErrors = $this->db->suppress_errors( true );
		$locked      = false;
		$lock        = 'amsec_bot_' . substr( hash( 'sha256', (string) ( $this->db->dbname ?? DB_NAME ) . ':' . $this->table ), 0, 32 );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Uncached bounded counter read.
			$exists = $this->db->get_var( $this->db->prepare( "SELECT 1 FROM {$this->table} WHERE address_key = %s", $key ) );
			if ( '' !== $this->db->last_error ) {
				return null;
			}
			if ( null === $exists ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Admission lock protects the global row budget; existing counters use atomic updates.
				$locked = 1 === (int) $this->db->get_var( $this->db->prepare( 'SELECT GET_LOCK(%s,0)', $lock ) );
				if ( ! $locked || '' !== $this->db->last_error ) {
					return null;
				}
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Recheck after another worker may have admitted this key.
				$exists = $this->db->get_var( $this->db->prepare( "SELECT 1 FROM {$this->table} WHERE address_key = %s", $key ) );
				if ( '' !== $this->db->last_error ) {
					return null;
				}
				if ( null === $exists ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- At most ten thousand opaque counter keys.
					$count = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
					if ( null === $count || '' !== $this->db->last_error || (int) $count >= 10000 ) {
						return null;
					}
				}
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Atomic upsert increments existing keys without a global lock.
			$result = $this->db->query( $this->db->prepare( "INSERT INTO {$this->table} (address_key,attempts,window_started_at,updated_at) VALUES (%s,1,%d,%d) ON DUPLICATE KEY UPDATE attempts=IF(window_started_at<=%d,1,LEAST(attempts+1,65535)),window_started_at=IF(window_started_at<=%d,%d,window_started_at),updated_at=%d", $key, $now, $now, $now - $window, $now - $window, $now, $now ) );
			if ( false === $result || '' !== $this->db->last_error ) {
				return null;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Concurrent attempts can make this count stricter, never undercount accepted writes.
			$count = $this->db->get_var( $this->db->prepare( "SELECT attempts FROM {$this->table} WHERE address_key=%s", $key ) );
			return null === $count || '' !== $this->db->last_error ? null : (int) $count;
		} catch ( \Throwable ) {
			return null;
		} finally {
			if ( $locked ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Release only the admission lock acquired above.
				$this->db->get_var( $this->db->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
			}
			$this->db->suppress_errors( $priorErrors );
		}
	}

	public function cleanup( int $now ): void {
		$prior = $this->db->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bounded retention removes only this plugin's old opaque counters.
			$this->db->query( $this->db->prepare( "DELETE FROM {$this->table} WHERE updated_at<%d ORDER BY updated_at LIMIT 1000", $now - DAY_IN_SECONDS ) );
		} finally {
			$this->db->suppress_errors( $prior );
		}
	}

	public function available(): bool {
		$prior = $this->db->suppress_errors( true );
		try {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Cheap read verifies counter storage availability.
			$value = $this->db->get_var( "SELECT COUNT(*) FROM {$this->table}" );
			if ( null === $value || (int) $value >= 10000 || '' !== $this->db->last_error ) {
				return false;
			}
			// Zero-row statements check INSERT and UPDATE permission without storing a probe or changing counters.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- No rows are inserted by this storage capability probe.
			$insert = $this->db->query( "INSERT INTO {$this->table} (address_key) SELECT address_key FROM {$this->table} WHERE 1=0" );
			if ( false === $insert || '' !== $this->db->last_error ) {
				return false;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- No rows are changed by this storage capability probe.
			$update = $this->db->query( "UPDATE {$this->table} SET attempts=attempts WHERE 1=0" );
			return false !== $update && '' === $this->db->last_error;
		} catch ( \Throwable ) {
			return false;
		} finally {
			$this->db->suppress_errors( $prior );
		}
	}
}
