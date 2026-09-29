<?php

// Run on a disposable site with wp eval-file.
use AmazingPlugins\Security\Login\RecoveryCodes;
use AmazingPlugins\Security\Login\WordPressTotpStore;

$id = wp_insert_user(
	array(
		'user_login' => 'amsec_totp_store_' . wp_generate_password( 8, false ),
		'user_pass'  => wp_generate_password( 32 ),
		'user_email' => 'amsec-store@example.invalid',
		'role'       => 'administrator',
	)
);
if ( is_wp_error( $id ) ) {
	throw new RuntimeException( 'Could not create fixture user.' );
}
try {
	$store = new WordPressTotpStore( $GLOBALS['wpdb'] );
	$code  = ( new RecoveryCodes() )->generate( 1 )[0];
	$hash  = password_hash( $code, PASSWORD_DEFAULT );
	if ( ! $store->enroll( $id, 'encrypted-fixture-seed', array( $hash ) ) || ! $store->isEnrolled( $id ) ) {
		throw new RuntimeException( 'Could not enroll fixture.' );
	}
	if ( ! $store->consumeStep( $id, 10 ) || $store->consumeStep( $id, 10 ) ) {
		throw new RuntimeException( 'TOTP step replay was accepted.' );
	}
	if ( ! $store->consumeRecoveryCode( $id, $code ) || $store->consumeRecoveryCode( $id, $code ) ) {
		throw new RuntimeException( 'Recovery code replay was accepted.' );
	}
	echo "TOTP store integration passed.\n";
} finally {
	wp_delete_user( $id );
}
