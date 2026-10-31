<?php

// Run on a disposable site with wp eval-file. The fixture restores the counter schema afterward.
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;
use AmazingPlugins\Security\Login\WordPressTotpStore;

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	define( 'WP_UNINSTALL_PLUGIN', 'amsec-security-scanner/amsec-security-scanner.php' );
}
$settings = new WordPressLoginSettings( new WordPressOptions() );
$store = new WordPressTotpStore( $GLOBALS['wpdb'] );
$userId = wp_insert_user( array( 'user_login' => 'amsec_uninstall_' . wp_generate_password( 8, false ), 'user_pass' => wp_generate_password( 32 ), 'user_email' => 'amsec-uninstall@example.invalid', 'role' => 'administrator' ) );
if ( is_wp_error( $userId ) ) {
	throw new RuntimeException( 'Could not create uninstall fixture user.' );
}
try {
	$store->enroll( $userId, 'encrypted-fixture-seed', array() );
	$settings->setRateMode( 'observe' );
	$settings->setEraseOnUninstall( false );
	include WP_PLUGIN_DIR . '/amsec-security-scanner/uninstall.php';
	if ( 'observe' !== $settings->rateMode() || ! $store->isEnrolled( $userId ) ) {
		throw new RuntimeException( 'Retain branch erased data.' );
	}
	$settings->setEraseOnUninstall( true );
	include WP_PLUGIN_DIR . '/amsec-security-scanner/uninstall.php';
	if ( 'off' !== $settings->rateMode() || $store->isEnrolled( $userId ) ) {
		throw new RuntimeException( 'Erase branch left login data.' );
	}
	echo "Login uninstall integration passed.\n";
} finally {
	wp_delete_user( $userId );
	WordPressRateCounterStore::install();
}
