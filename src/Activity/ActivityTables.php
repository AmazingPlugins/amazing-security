<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Activity;

final class ActivityTables {
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = $wpdb->prefix . 'amsec_activity';
		$collate = $wpdb->get_charset_collate();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Versioned plugin-owned bounded event table.
		dbDelta(
			"CREATE TABLE {$table} (
			id bigint unsigned NOT NULL AUTO_INCREMENT,
			event varchar(40) NOT NULL,
			actor_id bigint unsigned NOT NULL,
			user_id bigint unsigned NOT NULL,
			target varchar(190) NOT NULL,
			created_at bigint unsigned NOT NULL,
			PRIMARY KEY  (id),
			KEY event_time (event, created_at),
			KEY created_at (created_at)
		) {$collate} ENGINE=InnoDB;"
		);
		if ( '' === $wpdb->last_error ) {
			update_option( 'amsec_activity_schema_version', '1', false );
		}
		self::ensureScheduled();
	}

	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'amsec_activity_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_activity_cleanup' );
		}
	}
}
