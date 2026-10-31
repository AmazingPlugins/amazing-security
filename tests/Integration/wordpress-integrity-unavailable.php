<?php

// Run after a completed report on a disposable site; this action exits.
use AmazingPlugins\Security\Admin\IntegrityScanAction;

global $wp_version, $wp_local_package;
$locale = isset( $wp_local_package ) && $wp_local_package ? $wp_local_package : 'en_US';
$keys   = array( 'core:' . $wp_version . ':' . $locale, 'plugin:akismet:5.3.3' );
foreach ( $keys as $key ) {
	delete_transient( 'amsec_security_scanner_checksum_' . substr( hash( 'sha256', $key ), 0, 40 ) );
}
add_filter( 'pre_http_request', static fn() => new WP_Error( 'amsec_fixture_unavailable', 'Fixture blocks the checksum service.' ) );
wp_set_current_user( 1 );
$_POST['_wpnonce']    = wp_create_nonce( 'amsec_security_scanner_integrity_start' );
$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
( new IntegrityScanAction() )->start();
