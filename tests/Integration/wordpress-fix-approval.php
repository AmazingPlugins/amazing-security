<?php

// Run on a disposable WordPress site with AMSEC_CASE and `wp eval-file ... --user=admin`.
use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\FixTables;
use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

$case = getenv( 'AMSEC_CASE' );
$repo = new WordPressFixRepository( $GLOBALS['wpdb'] );
if ( 'prepare-observe' === $case || 'prepare-block' === $case ) {
	FixTables::install();
	// This fixture owns a disposable site; reset quotas from prior cases.
	$GLOBALS['wpdb']->query( 'DELETE FROM ' . $GLOBALS['wpdb']->prefix . 'amsec_fix_audit' );
	$GLOBALS['wpdb']->query( 'DELETE FROM ' . $GLOBALS['wpdb']->prefix . 'amsec_fix_proposals' );
	( new McpPreferences( new WordPressOptions() ) )->setEnabled( true );
	$before = 'prepare-observe' === $case ? 'off' : 'observe';
	$after  = 'prepare-observe' === $case ? 'observe' : 'block';
	update_option( 'amsec_login_rate_mode', $before, false );
	$id       = bin2hex( random_bytes( 16 ) );
	$now      = time();
	$proposal = new FixProposal( $id, str_repeat( 'a', 32 ), 'login-rate-' . $after, $before, $after, get_current_user_id(), $now, $now + 900 );
	if ( ! $repo->create( $proposal ) ) {
		throw new RuntimeException( 'Could not prepare proposal.' );
	}
	echo $id;
} elseif ( 'inspect' === $case ) {
	$id       = getenv( 'AMSEC_PROPOSAL_ID' );
	$proposal = $repo->get( $id );
	if ( null === $proposal ) {
		throw new RuntimeException( 'Proposal missing.' );
	}
	echo wp_json_encode(
		array(
			'status' => $proposal->status,
			'mode'   => get_option( 'amsec_login_rate_mode' ),
			'audit'  => array_column( $repo->audit( $id ), 'event' ),
		)
	);
} elseif ( 'approve-block-https' === $case || 'deny-block-password' === $case ) {
	$id       = getenv( 'AMSEC_PROPOSAL_ID' );
	$password = getenv( 'AMSEC_TEST_PASSWORD' );
	if ( ! preg_match( '/^[a-f0-9]{32}$/D', $id ) || ! is_string( $password ) || strlen( $password ) < 16 ) {
		throw new RuntimeException( 'Missing block test input.' );
	}
	wp_set_password( $password, 1 );
	clean_user_cache( 1 );
	wp_set_current_user( 0 );
	wp_set_current_user( 1 );
	$expires                       = time() + 3600;
	$token                         = WP_Session_Tokens::get_instance( 1 )->create( $expires );
	$_COOKIE[ SECURE_AUTH_COOKIE ] = wp_generate_auth_cookie( 1, $expires, 'secure_auth', $token );
	$_COOKIE[ LOGGED_IN_COOKIE ]   = wp_generate_auth_cookie( 1, $expires, 'logged_in', $token );
	$_SERVER['HTTPS']              = 'on';
	$_SERVER['REQUEST_METHOD']     = 'POST';
	$_POST                         = array(
		'proposal_id' => $id,
		'_wpnonce'    => wp_create_nonce( 'amsec_fix_approve_' . $id ),
		'confirm'     => '1',
		'password'    => 'deny-block-password' === $case ? 'incorrect' : $password,
	);
	$_REQUEST                      = $_POST;
	if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'amsec_fix_approve_' . $id ) || ! FixApprovalAction::cookieAuthenticated() ) {
		throw new RuntimeException( 'Secure cookie fixture did not authenticate.' );
	}
	( new FixApprovalAction() )->handle();
} elseif ( 'approve-observe-unverified' === $case ) {
	$id = getenv( 'AMSEC_PROPOSAL_ID' );
	wp_set_current_user( 1 );
	$expires                     = time() + 3600;
	$token                       = WP_Session_Tokens::get_instance( 1 )->create( $expires );
	$_COOKIE[ AUTH_COOKIE ]      = wp_generate_auth_cookie( 1, $expires, 'auth', $token );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( 1, $expires, 'logged_in', $token );
	$_SERVER['REQUEST_METHOD']   = 'POST';
	$_POST                       = array(
		'proposal_id' => $id,
		'_wpnonce'    => wp_create_nonce( 'amsec_fix_approve_' . $id ),
		'confirm'     => '1',
	);
	$_REQUEST                    = $_POST;
	update_option( 'amsec_security_scanner_latest_run', 'force-recheck-write', false );
	add_filter( 'pre_update_option_amsec_security_scanner_latest_run', static fn( $new, $old ) => $old, 10, 2 );
	add_filter(
		'wp_redirect',
		static function ( $url ) {
			if ( false === strpos( $url, 'verification=pending' ) ) {
				throw new RuntimeException( 'Failed recheck did not report unverified state.' );
			}
			return $url;
		}
	);
	( new FixApprovalAction() )->handle();
} elseif ( in_array( $case, array( 'deny-no-cookie', 'deny-stale-cookie', 'deny-editor-cookie' ), true ) ) {
	$id     = getenv( 'AMSEC_PROPOSAL_ID' );
	$userId = 1;
	if ( 'deny-editor-cookie' === $case ) {
		$editor = get_user_by( 'login', 'amsec_fixture_editor' );
		if ( ! $editor ) {
			$userId = wp_create_user( 'amsec_fixture_editor', bin2hex( random_bytes( 20 ) ), 'amsec-fixture-editor@example.test' );
			( new WP_User( $userId ) )->set_role( 'editor' );
		} else {
			$userId = $editor->ID;
		}
	}
	wp_set_current_user( $userId );
	if ( 'deny-no-cookie' !== $case ) {
		$expires                     = time() + 3600;
		$token                       = WP_Session_Tokens::get_instance( $userId )->create( $expires );
		$_COOKIE[ AUTH_COOKIE ]      = wp_generate_auth_cookie( $userId, $expires, 'auth', $token );
		$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $userId, $expires, 'logged_in', $token );
		if ( 'deny-stale-cookie' === $case ) {
			WP_Session_Tokens::get_instance( $userId )->destroy( $token );
		}
	}
	$_SERVER['REQUEST_METHOD'] = 'POST';
	$_POST                     = array(
		'proposal_id' => $id,
		'_wpnonce'    => wp_create_nonce( 'amsec_fix_approve_' . $id ),
		'confirm'     => '1',
	);
	$_REQUEST                  = $_POST;
	( new FixApprovalAction() )->handle();
} else {
	throw new RuntimeException( 'Unknown case.' );
}
