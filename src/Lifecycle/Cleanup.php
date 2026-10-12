<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Lifecycle;

use AmazingPlugins\Security\Free\TrafficGuard\HotlinkRule;

/** Cleanup shared by deactivation and uninstall. Uses only WordPress core functions so uninstall.php can load it directly. */
final class Cleanup {
	public const CRON_HOOKS = array(
		'amsec_local_daily_scan',
		'amsec_integrity_tick',
		'amsec_file_tick',
		'amsec_vuln_tick',
		'amsec_alert_retry',
		'amsec_login_cleanup',
		'amsec_fix_cleanup',
		'amsec_activity_cleanup',
		'amsec_bot_cleanup',
		'amsec_traffic_cleanup',
		'amsec_passkey_cleanup',
		'amsec_weekly_digest_tick',
	);

	/** Prefixes of options, transients and user meta that belong to this plugin. */
	public const PREFIXES = array( 'amsec_', 'amazing_security_' );

	public static function clearCron(): void {
		foreach ( self::CRON_HOOKS as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/** A cycle left "running" would resume on reactivation without anyone asking for it. */
	public static function resetScanCycle(): void {
		delete_option( 'amsec_suite_cycle' );
	}

	/** Remove the managed block this plugin may have added to uploads/.htaccess. Other lines stay. */
	public static function removeHotlinkBlock(): void {
		$path = WP_CONTENT_DIR . '/uploads/.htaccess';
		if ( ! is_file( $path ) || is_link( $path ) ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local uploads rule, not a remote request.
		$existing = file_get_contents( $path );
		if ( ! is_string( $existing ) || ! str_contains( $existing, HotlinkRule::BEGIN ) ) {
			return;
		}
		$next = HotlinkRule::strip( $existing );
		if ( '' === $next ) {
			wp_delete_file( $path );
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Remove only the managed block.
		file_put_contents( $path, $next, LOCK_EX );
	}

	/** Cached lookups and short-lived counters. Safe to drop at any time. */
	public static function deleteTransients(): void {
		global $wpdb;
		foreach ( self::PREFIXES as $prefix ) {
			$value   = $wpdb->esc_like( '_transient_' . $prefix ) . '%';
			$timeout = $wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Removes only this plugin's cached values.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $value, $timeout ) );
		}
	}

	/** Erase everything the plugin stored: options, user meta and its tables. Used only when the owner chose to erase data. */
	public static function eraseAllData(): void {
		global $wpdb;
		foreach ( self::PREFIXES as $prefix ) {
			$like = $wpdb->esc_like( $prefix ) . '%';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Erase selected by the owner.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like ) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Erase selected by the owner.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $like ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Lists this plugin's tables.
		$tables = $wpdb->get_col( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . 'amsec_' ) . '%' ) );
		foreach ( is_array( $tables ) ? $tables : array() as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Erase selected by the owner.
			$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $table ) );
		}
	}
}
