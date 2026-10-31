<?php

// Run only with wp eval-file on a disposable WordPress site.
use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

$mode    = getenv( 'AMSEC_RACE_MODE' );
$id      = getenv( 'AMSEC_RACE_ID' );
$marker  = getenv( 'AMSEC_RACE_MARKER' );
$release = getenv( 'AMSEC_RACE_RELEASE' );
$db      = $GLOBALS['wpdb'];
$repo    = new WordPressFixRepository( $db );

$waitForRelease = static function () use ( $marker, $release ): void {
	if ( ! is_string( $marker ) || ! is_string( $release ) || ! str_starts_with( $marker, WP_CONTENT_DIR . '/amsec-race-' ) || ! str_starts_with( $release, WP_CONTENT_DIR . '/amsec-race-' ) ) {
		throw new RuntimeException( 'Invalid race barriers.' );
	}
	file_put_contents( $marker, 'locked' );
	$deadline = microtime( true ) + 20;
	while ( ! file_exists( $release ) && microtime( true ) < $deadline ) {
		usleep( 100000 );
	}
	if ( ! file_exists( $release ) ) {
		throw new RuntimeException( 'Race barrier timed out.' );
	}
};

if ( 'setup' === $mode ) {
	( new McpPreferences( new WordPressOptions() ) )->setEnabled( true );
	delete_option( 'amsec_login_rate_mode' );
	$id       = bin2hex( random_bytes( 16 ) );
	$now      = time();
	$proposal = new FixProposal( $id, str_repeat( 'a', 32 ), 'login-rate-observe', 'off', 'observe', 1, $now, $now + 900 );
	if ( ! $repo->create( $proposal ) ) {
		throw new RuntimeException( 'Could not create race proposal.' );
	}
	echo $id;
	return;
}

if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
	throw new RuntimeException( 'Invalid proposal ID.' );
}

if ( 'optout_hold' === $mode ) {
	$db->query( 'START TRANSACTION' );
	$db->get_row( $db->prepare( "SELECT option_value FROM {$db->options} WHERE option_name = %s FOR UPDATE", 'amsec_security_scanner_mcp_enabled' ) );
	if ( '' !== $db->last_error || 1 !== $db->query( $db->prepare( "UPDATE {$db->options} SET option_value = %s WHERE option_name = %s", '0', 'amsec_security_scanner_mcp_enabled' ) ) ) {
		throw new RuntimeException( 'Could not lock and turn off MCP.' );
	}
	$waitForRelease();
	$db->query( 'COMMIT' );
	echo "opt-out committed\n";
} elseif ( 'apply' === $mode ) {
	echo $repo->apply( $id, 1, time() ) . "\n";
} elseif ( 'apply_hold' === $mode ) {
	$holding = new WordPressFixRepository( $db, $waitForRelease );
	echo $holding->apply( $id, 1, time() ) . "\n";
} elseif ( 'optout' === $mode ) {
	if ( 1 !== $db->query( $db->prepare( "UPDATE {$db->options} SET option_value = %s WHERE option_name = %s", '0', 'amsec_security_scanner_mcp_enabled' ) ) ) {
		throw new RuntimeException( 'Could not turn off MCP after approval.' );
	}
	echo "opt-out committed\n";
} elseif ( 'assert_optout_first' === $mode || 'assert_approval_first' === $mode ) {
	$proposal        = $repo->get( $id );
	$permission      = $db->get_var( $db->prepare( "SELECT option_value FROM {$db->options} WHERE option_name = %s", 'amsec_security_scanner_mcp_enabled' ) );
	$expectedStatus  = 'assert_optout_first' === $mode ? 'pending' : 'applied';
	$expectedSetting = 'assert_optout_first' === $mode ? 'off' : 'observe';
	$expectedEvents  = 'assert_optout_first' === $mode ? array() : array( 'applied' );
	if ( null === $proposal || $proposal->status !== $expectedStatus || get_option( 'amsec_login_rate_mode', 'off' ) !== $expectedSetting || array_column( $repo->audit( $id ), 'event' ) !== $expectedEvents || '0' !== $permission ) {
		throw new RuntimeException( 'Unexpected final proposal, setting, audit, or permission.' );
	}
	echo "proposal, setting, audit, and permission consistent\n";
} else {
	throw new RuntimeException( 'Unknown race mode.' );
}
