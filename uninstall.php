<?php

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) || ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( '1' !== get_option( 'amsec_login_erase_on_uninstall' ) ) {
	return;
}

global $wpdb;

delete_option( 'amsec_login_rate_mode' );
delete_option( 'amsec_login_xmlrpc_disabled' );
delete_option( 'amsec_login_erase_on_uninstall' );
delete_option( 'amsec_login_schema_version' );
delete_option( 'amsec_fix_schema_version' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes plugin records once; caching has no value.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s, %s, %s)", 'amsec_totp_v1', 'amsec_totp_recovery_at', 'amsec_password_reset_required', 'amsec_required_totp_grace' ) );

$amsec_pending_pattern = $wpdb->esc_like( '_transient_amsec_totp_pending_' ) . '%';
$amsec_timeout_pattern = $wpdb->esc_like( '_transient_timeout_amsec_totp_pending_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes only pending encrypted seeds once.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $amsec_pending_pattern, $amsec_timeout_pattern ) );

$amsec_table = $wpdb->prefix . 'amsec_login_rate';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Drop only this plugin's counter table after explicit erase selection.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amsec_table ) );

$amsec_fix_proposals = $wpdb->prefix . 'amsec_fix_proposals';
$amsec_fix_audit     = $wpdb->prefix . 'amsec_fix_audit';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Explicit erase selection removes plugin-owned fix records.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amsec_fix_proposals ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Explicit erase selection removes plugin-owned audit records.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amsec_fix_audit ) );

delete_option( 'amsec_activity_schema_version' );
delete_option( 'amsec_activity_enabled' );
wp_clear_scheduled_hook( 'amsec_activity_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only plugin-owned activity history.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'amsec_activity' ) );

delete_option( 'amsec_required_totp_policy' );

delete_option( 'amsec_custom_baseline_state' );

delete_option( 'amsec_bot_mode' );
delete_option( 'amsec_bot_schema_version' );
wp_clear_scheduled_hook( 'amsec_bot_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only plugin-owned opaque counters.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'amsec_bot_rate' ) );

delete_option( 'amsec_digest_enabled' );
delete_option( 'amsec_digest_state' );
delete_option( 'amsec_digest_lock' );
wp_clear_scheduled_hook( 'amsec_weekly_digest_tick' );

delete_option( 'amsec_content_state' );
	delete_option( 'amsec_repository_state' );
	delete_option( 'amsec_exposure_state' );
	delete_option( 'amsec_exposure_lock' );
	delete_option( 'amsec_repository_lock' );
delete_option( 'amsec_content_lock' );

delete_option( 'amsec_headers_state' );
delete_option( 'amsec_headers_lock' );

delete_option( 'amsec_rest_rate_policy' );

delete_option( 'amsec_network_policy' );
delete_option( 'amsec_network_observation' );

delete_option( 'amsec_traffic_policy' );
delete_option( 'amsec_traffic_schema_version' );
wp_clear_scheduled_hook( 'amsec_traffic_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned traffic history.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'amsec_traffic' ) );

delete_option( 'amsec_proxy_policy' );

delete_option( 'amsec_passkey_policy' );
delete_option( 'amsec_passkey_schema_version' );
wp_clear_scheduled_hook( 'amsec_passkey_cleanup' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned public keys and pending operations.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'amsec_passkey_credentials' ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only feature-owned pending operations.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->prefix . 'amsec_passkey_pending' ) );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Explicit erase preference removes only opaque feature-owned account handles.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key=%s", 'amsec_passkey_handle' ) );

delete_option( 'amsec_idle_minutes' );
delete_option( 'amsec_approve_registrations' );
delete_option( 'amsec_email_factor' );
delete_option( 'amsec_login_challenge' );
delete_option( 'amsec_ai_endpoint' );
delete_option( 'amsec_ai_model' );
delete_option( 'amsec_ai_key' );
delete_option( 'amsec_block_hostnames' );
delete_option( 'amsec_block_agents' );
delete_option( 'amsec_block_referrers' );
delete_option( 'amsec_live_traffic' );
delete_option( 'amsec_live_traffic_rows' );
delete_option( 'amsec_hotlink' );
delete_option( 'amsec_precise_block' );
delete_option( 'amsec_login_email' );
delete_option( 'amsec_comment_honeypot' );
delete_option( 'amsec_comment_rate' );
delete_option( 'amsec_comment_spam_hold' );
delete_option( 'amsec_comment_spam_hashes' );
delete_option( 'amsec_event_mail' );
delete_option( 'amsec_password_min_length' );
delete_option( 'amsec_password_require_number' );
delete_option( 'amsec_password_require_mixed' );
delete_option( 'amsec_password_require_symbol' );
delete_option( 'amsec_password_block_name' );
delete_option( 'amsec_password_block_reuse' );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only these account-protection rows.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s, %s, %s)", 'amsec_last_seen', 'amsec_registration_pending', 'amsec_email_factor_pending', 'amsec_login_email_sent' ) );
$amsec_challenge_pattern = $wpdb->esc_like( '_transient_amsec_lc_' ) . '%';
$amsec_challenge_timeout = $wpdb->esc_like( '_transient_timeout_amsec_lc_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only the on-site login-question transients.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $amsec_challenge_pattern, $amsec_challenge_timeout ) );
$amsec_comment_rate         = $wpdb->esc_like( '_transient_amsec_cr_' ) . '%';
$amsec_comment_rate_timeout = $wpdb->esc_like( '_transient_timeout_amsec_cr_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit erase removes only the comment-minute transients.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $amsec_comment_rate, $amsec_comment_rate_timeout ) );
