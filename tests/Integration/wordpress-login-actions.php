<?php

// Run with AMSEC_CASE=editor|forged|save and WP-CLI eval-file on a disposable site.
use AmazingPlugins\Security\Admin\LoginSettingsAction;

$case = getenv( 'AMSEC_CASE' );
if ( 'editor' === $case ) {
	$user = get_user_by( 'login', 'amsec_login_editor' );
	if ( ! $user ) {
		$id = wp_insert_user(
			array(
				'user_login' => 'amsec_login_editor',
				'user_pass'  => wp_generate_password( 32 ),
				'user_email' => 'amsec-login-editor@example.invalid',
				'role'       => 'editor',
			)
		);
		if ( is_wp_error( $id ) ) {
			throw new RuntimeException( 'Could not create editor.' );
		}
		$user = get_user_by( 'id', $id );
	}
	wp_set_current_user( $user->ID );
} else {
	wp_set_current_user( 1 );
}
$_POST['rate_mode']       = 'observe';
$_POST['xmlrpc_disabled'] = '1';
$_POST['_wpnonce']        = 'forged' === $case ? 'invalid' : wp_create_nonce( 'amsec_login_settings' );
$_REQUEST['_wpnonce']     = $_POST['_wpnonce'];
( new LoginSettingsAction() )->save();
