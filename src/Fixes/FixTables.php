<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Fixes;

defined( 'ABSPATH' ) || exit;

final class FixTables {
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$proposals = $wpdb->prefix . 'amsec_fix_proposals';
		$audit     = $wpdb->prefix . 'amsec_fix_audit';
		$collate   = $wpdb->get_charset_collate();
		$schema    = "CREATE TABLE {$proposals} (
			id char(32) NOT NULL,
			finding_id char(32) NOT NULL,
			recipe_id varchar(40) NOT NULL,
			before_mode varchar(10) NOT NULL,
			after_mode varchar(10) NOT NULL,
			fingerprint char(64) NOT NULL,
			requester_id bigint unsigned NOT NULL,
			approver_id bigint unsigned NULL,
			status varchar(20) NOT NULL,
			created_at bigint unsigned NOT NULL,
			expires_at bigint unsigned NOT NULL,
			applied_at bigint unsigned NULL,
			rolled_back_at bigint unsigned NULL,
			PRIMARY KEY  (id),
			KEY requester_created (requester_id, created_at),
			KEY status_expiry (status, expires_at)
		) {$collate} ENGINE=InnoDB;";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Versioned plugin-owned tables for atomic fix approval.
		dbDelta( $schema );
		$schema = "CREATE TABLE {$audit} (
			event_id bigint unsigned NOT NULL AUTO_INCREMENT,
			proposal_id char(32) NOT NULL,
			event varchar(20) NOT NULL,
			actor_id bigint unsigned NOT NULL,
			created_at bigint unsigned NOT NULL,
			reason varchar(40) NOT NULL,
			PRIMARY KEY  (event_id),
			KEY proposal_id (proposal_id),
			KEY created_at (created_at)
		) {$collate} ENGINE=InnoDB;";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Versioned plugin-owned audit table.
		dbDelta( $schema );
		update_option( 'amsec_fix_schema_version', '1', false );
		self::ensureScheduled();
	}

	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'amsec_fix_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_fix_cleanup' );
		}
	}
}
