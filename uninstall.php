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

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Erase only this plugin's per-user second-factor records when the owner opted in.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s)", 'amsec_totp_v1', 'amsec_totp_recovery_at' ) );

$pendingPattern = $wpdb->esc_like( '_transient_amsec_totp_pending_' ) . '%';
$timeoutPattern = $wpdb->esc_like( '_transient_timeout_amsec_totp_pending_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Remove pending encrypted seeds with this plugin's exact transient prefix.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $pendingPattern, $timeoutPattern ) );

$table = $wpdb->prefix . 'amsec_login_rate';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Remove the versioned login counter table only after explicit erase-on-uninstall selection.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $table ) );
