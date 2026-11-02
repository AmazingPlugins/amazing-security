<?php

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( '1' !== get_option( 'ironlatch_login_erase_on_uninstall' ) ) {
	return;
}

global $wpdb;

delete_option( 'ironlatch_login_rate_mode' );
delete_option( 'ironlatch_login_xmlrpc_disabled' );
delete_option( 'ironlatch_login_erase_on_uninstall' );
delete_option( 'ironlatch_login_schema_version' );
delete_option( 'ironlatch_fix_schema_version' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes plugin records once; caching has no value.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s, %s, %s)", 'ironlatch_totp_v1', 'ironlatch_totp_recovery_at', 'ironlatch_password_reset_required', 'ironlatch_required_totp_grace' ) );

$ironlatch_pending_pattern = $wpdb->esc_like( '_transient_ironlatch_totp_pending_' ) . '%';
$ironlatch_timeout_pattern = $wpdb->esc_like( '_transient_timeout_ironlatch_totp_pending_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes only pending encrypted seeds once.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $ironlatch_pending_pattern, $ironlatch_timeout_pattern ) );

$ironlatch_table = $wpdb->prefix . 'ironlatch_login_rate';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Drop only this plugin's counter table after explicit erase selection.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $ironlatch_table ) );

$ironlatch_fix_proposals = $wpdb->prefix . 'ironlatch_fix_proposals';
$ironlatch_fix_audit     = $wpdb->prefix . 'ironlatch_fix_audit';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Explicit erase selection removes plugin-owned fix records.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $ironlatch_fix_proposals ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Explicit erase selection removes plugin-owned audit records.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $ironlatch_fix_audit ) );

delete_option( 'ironlatch_activity_schema_version' );
delete_option( 'ironlatch_activity_enabled' );
wp_clear_scheduled_hook( 'ironlatch_activity_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only plugin-owned activity history.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ironlatch_activity' ) );

delete_option( 'ironlatch_required_totp_policy' );

delete_option( 'ironlatch_custom_baseline_state' );

delete_option( 'ironlatch_bot_mode' );
delete_option( 'ironlatch_scanner_mode' );
delete_option( 'ironlatch_rate_limits' );
delete_option( 'ironlatch_rate_limit_recent' );
delete_option( 'ironlatch_bot_schema_version' );
wp_clear_scheduled_hook( 'ironlatch_bot_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only plugin-owned opaque counters.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ironlatch_bot_rate' ) );

delete_option( 'ironlatch_security_scanner_kev_enabled' );
delete_option( 'ironlatch_security_scanner_kev_ids' );
delete_option( 'ironlatch_security_scanner_kev_fetched' );

delete_option( 'ironlatch_digest_enabled' );
delete_option( 'ironlatch_digest_state' );
delete_option( 'ironlatch_digest_lock' );
wp_clear_scheduled_hook( 'ironlatch_weekly_digest_tick' );

delete_option( 'ironlatch_content_state' );
	delete_option( 'ironlatch_repository_state' );
	delete_option( 'ironlatch_exposure_state' );
	delete_option( 'ironlatch_exposure_lock' );
	delete_option( 'ironlatch_repository_lock' );
delete_option( 'ironlatch_content_lock' );

delete_option( 'ironlatch_headers_state' );
delete_option( 'ironlatch_scan_headers' );
delete_option( 'ironlatch_headers_lock' );

delete_option( 'ironlatch_rest_rate_policy' );

delete_option( 'ironlatch_network_policy' );
delete_option( 'ironlatch_network_observation' );

delete_option( 'ironlatch_traffic_policy' );
delete_option( 'ironlatch_traffic_schema_version' );
wp_clear_scheduled_hook( 'ironlatch_traffic_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned traffic history.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ironlatch_traffic' ) );

delete_option( 'ironlatch_proxy_policy' );

delete_option( 'ironlatch_passkey_policy' );
delete_option( 'ironlatch_passkey_schema_version' );
wp_clear_scheduled_hook( 'ironlatch_passkey_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned public keys and pending operations.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ironlatch_passkey_credentials' ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned pending operations.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'ironlatch_passkey_pending' ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only opaque feature-owned account handles.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key=%s", 'ironlatch_passkey_handle' ) );

delete_option( 'ironlatch_idle_minutes' );
delete_option( 'ironlatch_approve_registrations' );
delete_option( 'ironlatch_email_factor' );
delete_option( 'ironlatch_login_challenge' );
delete_option( 'ironlatch_ai_endpoint' );
delete_option( 'ironlatch_ai_model' );
delete_option( 'ironlatch_ai_key' );
delete_option( 'ironlatch_block_hostnames' );
delete_option( 'ironlatch_block_agents' );
delete_option( 'ironlatch_block_referrers' );
delete_option( 'ironlatch_live_traffic' );
delete_option( 'ironlatch_live_traffic_rows' );
delete_option( 'ironlatch_hotlink' );
delete_option( 'ironlatch_precise_block' );
delete_option( 'ironlatch_login_email' );
delete_option( 'ironlatch_comment_honeypot' );
delete_option( 'ironlatch_comment_rate' );
delete_option( 'ironlatch_comment_spam_hold' );
delete_option( 'ironlatch_comment_spam_hashes' );
delete_option( 'ironlatch_event_mail' );
delete_option( 'ironlatch_password_min_length' );
delete_option( 'ironlatch_password_require_number' );
delete_option( 'ironlatch_password_require_mixed' );
delete_option( 'ironlatch_password_require_symbol' );
delete_option( 'ironlatch_password_block_name' );
delete_option( 'ironlatch_password_block_reuse' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only these account-protection rows.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s, %s, %s)", 'ironlatch_last_seen', 'ironlatch_registration_pending', 'ironlatch_email_factor_pending', 'ironlatch_login_email_sent' ) );
$ironlatch_challenge_pattern = $wpdb->esc_like( '_transient_ironlatch_lc_' ) . '%';
$ironlatch_challenge_timeout = $wpdb->esc_like( '_transient_timeout_ironlatch_lc_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only the on-site login-question transients.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $ironlatch_challenge_pattern, $ironlatch_challenge_timeout ) );
$ironlatch_comment_rate         = $wpdb->esc_like( '_transient_ironlatch_cr_' ) . '%';
$ironlatch_comment_rate_timeout = $wpdb->esc_like( '_transient_timeout_ironlatch_cr_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only the comment-minute transients.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $ironlatch_comment_rate, $ironlatch_comment_rate_timeout ) );

// Sweep every remaining plugin-owned option, transient, user meta row and cron hook. Both prefixes belong only to this plugin.
foreach ( array( 'ironlatch\_%', 'amazing\_security\_%', '\_transient\_ironlatch\_%', '\_transient\_timeout\_ironlatch\_%', '\_transient\_amazing\_security\_%', '\_transient\_timeout\_amazing\_security\_%', '\_site\_transient\_ironlatch\_%', '\_site\_transient\_timeout\_ironlatch\_%' ) as $ironlatch_like ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only rows with this plugin's prefixes.
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $ironlatch_like ) );
}
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only this plugin's user meta.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", 'ironlatch\_%' ) );
foreach ( array( 'ironlatch_activity_cleanup', 'ironlatch_alert_retry', 'ironlatch_bot_cleanup', 'ironlatch_file_tick', 'ironlatch_fix_cleanup', 'ironlatch_integrity_tick', 'ironlatch_local_code_tick', 'ironlatch_local_daily_scan', 'ironlatch_login_cleanup', 'ironlatch_passkey_cleanup', 'ironlatch_traffic_cleanup', 'ironlatch_vuln_tick', 'ironlatch_weekly_digest_tick' ) as $ironlatch_hook ) {
	wp_clear_scheduled_hook( $ironlatch_hook );
}
wp_cache_flush();
