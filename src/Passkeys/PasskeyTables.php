<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyTables {
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$credentials = $wpdb->prefix . 'amsec_passkey_credentials';
		$pending     = $wpdb->prefix . 'amsec_passkey_pending';
		$collate     = $wpdb->get_charset_collate();
	 // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Plugin-owned bounded public credential storage and indexed ownership.
		dbDelta(
			"CREATE TABLE {$credentials} (
   id char(64) NOT NULL,
   user_id bigint unsigned NOT NULL,
   created_at bigint unsigned NOT NULL,
   record text NOT NULL,
   PRIMARY KEY  (id),
   KEY user_created (user_id,created_at)
  ) {$collate} ENGINE=InnoDB;"
		);
		$okay = '' === $wpdb->last_error;
	 // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Plugin-owned one-use bounded pending operations; no private key/assertion storage.
		dbDelta(
			"CREATE TABLE {$pending} (
   ticket_hash char(64) NOT NULL,
   user_id bigint unsigned NOT NULL,
   created_at bigint unsigned NOT NULL,
   expires_at bigint unsigned NOT NULL,
   claimed_at bigint unsigned NOT NULL DEFAULT 0,
   record text NOT NULL,
   PRIMARY KEY  (ticket_hash),
   KEY user_id (user_id),
   KEY created_at (created_at),
   KEY expires_at (expires_at)
  ) {$collate} ENGINE=InnoDB;"
		);
		if ( $okay && '' === $wpdb->last_error ) {
			update_option( 'amsec_passkey_schema_version', '1', false ); }
		self::ensureScheduled();
	}
	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'amsec_passkey_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'amsec_passkey_cleanup' ); }
	}
}
