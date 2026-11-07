<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

use AmazingPlugins\Security\Database\SchemaCheck;

defined( 'ABSPATH' ) || exit;

final class TrafficTables {
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = $wpdb->prefix . 'ironlatch_traffic';
		$collate = $wpdb->get_charset_collate();
	 // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- Versioned bounded plugin-owned history table.
		dbDelta(
			"CREATE TABLE {$table} (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  created_at bigint unsigned NOT NULL,
  method varchar(8) NOT NULL,
  category varchar(16) NOT NULL,
  status smallint unsigned NOT NULL,
  decision varchar(20) NOT NULL,
  PRIMARY KEY  (id),
  KEY created_at (created_at),
  KEY category_time (category, created_at)
  ) {$collate} ENGINE=InnoDB;"
		);
		SchemaCheck::record( 'ironlatch_traffic_schema_version', '1', $wpdb, $table );
		self::ensureScheduled();
	}
	public static function ensureScheduled(): void {
		if ( ! wp_next_scheduled( 'ironlatch_traffic_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'ironlatch_traffic_cleanup' ); } }
}
