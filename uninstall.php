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

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes plugin records once; caching has no value.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s)", 'amsec_totp_v1', 'amsec_totp_recovery_at' ) );

$amsec_pending_pattern = $wpdb->esc_like( '_transient_amsec_totp_pending_' ) . '%';
$amsec_timeout_pattern = $wpdb->esc_like( '_transient_timeout_amsec_totp_pending_' ) . '%';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall removes only pending encrypted seeds once.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $amsec_pending_pattern, $amsec_timeout_pattern ) );

$amsec_table = $wpdb->prefix . 'amsec_login_rate';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Drop only this plugin's counter table after explicit erase selection.
$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $amsec_table ) );
