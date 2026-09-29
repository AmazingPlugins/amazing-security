<?php

// Run with wp eval-file on a disposable site. It never prints secret or recovery values.
use AmazingPlugins\Security\Login\RecoveryCodes;
use AmazingPlugins\Security\Login\SecretCipher;
use AmazingPlugins\Security\Login\Totp;
use AmazingPlugins\Security\Login\TotpEnrollment;
use AmazingPlugins\Security\Login\WordPressPendingEnrollmentStore;
use AmazingPlugins\Security\Login\WordPressTotpStore;

$id = wp_insert_user(
	array(
		'user_login' => 'amsec_totp_enrollment_' . wp_generate_password( 8, false ),
		'user_pass'  => wp_generate_password( 32 ),
		'user_email' => 'amsec-enrollment@example.invalid',
		'role'       => 'administrator',
	)
);
if ( is_wp_error( $id ) ) {
	throw new RuntimeException( 'Could not create fixture user.' );
}
wp_set_current_user( $id );
try {
	$store = new WordPressTotpStore( $GLOBALS['wpdb'] );
	$pending = new WordPressPendingEnrollmentStore();
	$cipher = new SecretCipher( wp_salt( 'auth' ) );
	$totp = new Totp();
	$enrollment = new TotpEnrollment( $store, $pending, $cipher, $totp, new RecoveryCodes() );
	if ( $enrollment->begin( $id, false )->allowed ) {
		throw new RuntimeException( 'Insecure enrollment was allowed.' );
	}
	if ( ! $enrollment->begin( $id, true )->allowed ) {
		throw new RuntimeException( 'HTTPS enrollment was denied.' );
	}
	$seed = $cipher->decrypt( $pending->get( $id ) );
	$codes = $enrollment->confirm( $id, $totp->atStep( $seed, intdiv( time(), 30 ) ) );
	if ( 10 !== count( $codes ) || ! $store->isEnrolled( $id ) || null !== $pending->get( $id ) ) {
		throw new RuntimeException( 'Enrollment did not activate and clear pending data.' );
	}
	if ( ! $enrollment->disable( $id, $codes[0] ) || $store->isEnrolled( $id ) ) {
		throw new RuntimeException( 'Recovery-code disable failed.' );
	}
	echo "TOTP enrollment integration passed.\n";
} finally {
	wp_delete_user( $id );
}
