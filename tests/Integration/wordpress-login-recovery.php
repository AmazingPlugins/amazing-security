<?php

// Run with wp eval-file on a disposable WordPress fixture.
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\LoginRecoveryCommand;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressTotpStore;

$settings  = new WordPressLoginSettings( new WordPressOptions() );
$oldMode   = $settings->rateMode();
$oldXmlRpc = $settings->xmlRpcAuthDisabled();
$id        = wp_insert_user(
	array(
		'user_login' => 'amsec_cli_' . wp_generate_password( 8, false ),
		'user_pass'  => wp_generate_password( 32 ),
		'user_email' => 'amsec-cli@example.invalid',
		'role'       => 'administrator',
	)
);
if ( is_wp_error( $id ) ) {
	throw new RuntimeException( 'Could not create CLI fixture user.' );
}
try {
	$store = new WordPressTotpStore( $GLOBALS['wpdb'] );
	$store->enroll( $id, 'encrypted-fixture-seed', array( password_hash( str_repeat( 'f', 24 ), PASSWORD_DEFAULT ) ) );
	$settings->setRateMode( 'block' );
	$settings->setXmlRpcAuthDisabled( true );
	$command = new LoginRecoveryCommand();
	$command->disableLogin( array(), array() );
	if ( 'off' !== $settings->rateMode() || $settings->xmlRpcAuthDisabled() ) {
		throw new RuntimeException( 'Emergency login disable failed.' );
	}
	$command->disableTotp( array(), array( 'user' => (string) $id ) );
	if ( $store->isEnrolled( $id ) || ! get_user_meta( $id, 'amsec_totp_recovery_at', true ) ) {
		throw new RuntimeException( 'Emergency TOTP disable failed.' );
	}
	echo "Login recovery integration passed.\n";
} finally {
	$settings->setRateMode( $oldMode );
	$settings->setXmlRpcAuthDisabled( $oldXmlRpc );
	wp_delete_user( $id );
}
