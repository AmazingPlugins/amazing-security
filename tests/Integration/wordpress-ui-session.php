<?php
// Disposable site only. Redirect stdout to a mode-0600 temporary file; it contains session cookies.
$login = 'amsec-ui-' . bin2hex( random_bytes( 5 ) );
$id = wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password( 40, true ), 'user_email' => $login . '@example.test', 'role' => 'administrator' ) );
if ( is_wp_error( $id ) ) { throw new RuntimeException( 'Could not create UI reviewer.' ); }
add_option( 'amsec_ui_original_urls', array( 'home' => get_option( 'home' ), 'siteurl' => get_option( 'siteurl' ) ), '', false );
update_option( 'home', 'http://127.0.0.1:18889' );
update_option( 'siteurl', 'http://127.0.0.1:18889' );
$expires = time() + 7200;
$cookies = array();
foreach ( array( array( AUTH_COOKIE, 'auth', '/wp-admin' ), array( LOGGED_IN_COOKIE, 'logged_in', '/' ) ) as [ $name, $scheme, $path ] ) {
	$cookies[] = array( 'name' => $name, 'value' => wp_generate_auth_cookie( $id, $expires, $scheme ), 'domain' => '127.0.0.1', 'path' => $path, 'expires' => $expires, 'httpOnly' => true, 'secure' => false, 'sameSite' => 'Lax' );
}
echo wp_json_encode( array( 'login' => $login, 'cookies' => $cookies ) );
