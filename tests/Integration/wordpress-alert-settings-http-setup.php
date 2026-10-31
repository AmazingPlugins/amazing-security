<?php

// Run only with wp eval-file on a disposable WordPress site.
$login    = getenv( 'AMSEC_TEST_LOGIN' );
$password = getenv( 'AMSEC_TEST_PASSWORD' );
if ( ! is_string( $login ) || ! is_string( $password ) || '' === $login || '' === $password ) {
	throw new RuntimeException( 'Missing test credentials.' );
}
$user = wp_create_user( $login, $password, $login . '@example.test' );
if ( is_wp_error( $user ) ) {
	throw new RuntimeException( 'Could not create disposable administrator.' );
}
( new WP_User( $user ) )->set_role( 'administrator' );
echo 'Fixture ready.';
