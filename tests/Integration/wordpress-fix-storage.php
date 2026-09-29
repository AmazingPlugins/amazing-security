<?php

// Run on a disposable WordPress site with `wp eval-file ... --user=admin`.
use AmazingPlugins\Security\Fixes\FixProposal;
use AmazingPlugins\Security\Fixes\FixTables;
use AmazingPlugins\Security\Fixes\WordPressFixRepository;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

FixTables::install();
( new McpPreferences( new WordPressOptions() ) )->setEnabled( true );
$GLOBALS['wpdb']->query( 'DELETE FROM ' . $GLOBALS['wpdb']->prefix . 'amsec_fix_audit' );
$GLOBALS['wpdb']->query( 'DELETE FROM ' . $GLOBALS['wpdb']->prefix . 'amsec_fix_proposals' );
delete_option( 'amsec_login_rate_mode' );
$now  = time();
$repo = new WordPressFixRepository( $GLOBALS['wpdb'] );
$id   = bin2hex( random_bytes( 16 ) );
$proposal = new FixProposal( $id, str_repeat( 'a', 32 ), 'login-rate-observe', 'off', 'observe', 1, $now, $now + 900 );
if ( ! $repo->create( $proposal ) || 'applied' !== $repo->apply( $id, 1, $now + 1 ) || 'observe' !== get_option( 'amsec_login_rate_mode' ) ) {
	throw new RuntimeException( 'Atomic apply failed.' );
}
if ( 'already_used' !== $repo->apply( $id, 1, $now + 2 ) || 1 !== count( $repo->audit( $id ) ) ) {
	throw new RuntimeException( 'Approval replay was not denied.' );
}
if ( 'rolled_back' !== $repo->rollback( $id, 1, $now + 3 ) || 'off' !== get_option( 'amsec_login_rate_mode' ) || 'already_used' !== $repo->rollback( $id, 1, $now + 4 ) ) {
	throw new RuntimeException( 'Rollback failed or replayed.' );
}

$staleId = bin2hex( random_bytes( 16 ) );
update_option( 'amsec_login_rate_mode', 'observe', false );
$stale   = new FixProposal( $staleId, str_repeat( 'b', 32 ), 'login-rate-block', 'observe', 'block', 1, $now, $now + 900 );
$repo->create( $stale );
update_option( 'amsec_login_rate_mode', 'off', false );
if ( 'stale' !== $repo->apply( $staleId, 1, $now + 1 ) || 'off' !== get_option( 'amsec_login_rate_mode' ) ) {
	throw new RuntimeException( 'Changed target was overwritten.' );
}

$failureId = bin2hex( random_bytes( 16 ) );
$failure   = new FixProposal( $failureId, str_repeat( 'c', 32 ), 'login-rate-observe', 'off', 'observe', 1, $now, $now + 900 );
$faulty    = new WordPressFixRepository( $GLOBALS['wpdb'], static function (): void { throw new RuntimeException( 'Injected audit failure.' ); } );
$repo->create( $failure );
if ( 'unavailable' !== $faulty->apply( $failureId, 1, $now + 1 ) || 'off' !== get_option( 'amsec_login_rate_mode' ) || 'pending' !== $repo->get( $failureId )->status ) {
	throw new RuntimeException( 'Audit failure did not roll back the setting and proposal.' );
}
for ( $n = 0; $n < 6; ++$n ) {
	$quotaId  = bin2hex( random_bytes( 16 ) );
	$quota    = new FixProposal( $quotaId, str_repeat( 'd', 32 ), 'login-rate-observe', 'off', 'observe', 2, $now + $n, $now + $n + 900 );
	$created  = $repo->create( $quota );
	if ( $created !== ( $n < 5 ) ) {
		throw new RuntimeException( 'Per-administrator proposal quota failed.' );
	}
}
$tamperedId = bin2hex( random_bytes( 16 ) );
$tampered   = new FixProposal( $tamperedId, str_repeat( 'e', 32 ), 'login-rate-observe', 'off', 'observe', 3, $now, $now + 900 );
$repo->create( $tampered );
$GLOBALS['wpdb']->update( $GLOBALS['wpdb']->prefix . 'amsec_fix_proposals', array( 'fingerprint' => str_repeat( '0', 64 ) ), array( 'id' => $tamperedId ) );
if ( 'unavailable' !== $repo->apply( $tamperedId, 1, $now + 1 ) || 'off' !== get_option( 'amsec_login_rate_mode' ) ) {
	throw new RuntimeException( 'Changed proposal fingerprint was accepted.' );
}
$optOutId = bin2hex( random_bytes( 16 ) );
$optOut   = new FixProposal( $optOutId, str_repeat( 'f', 32 ), 'login-rate-observe', 'off', 'observe', 4, $now, $now + 900 );
$repo->create( $optOut );
( new McpPreferences( new WordPressOptions() ) )->setEnabled( false );
if ( 'unavailable' !== $repo->apply( $optOutId, 1, $now + 1 ) || 'off' !== get_option( 'amsec_login_rate_mode' ) || 'pending' !== $repo->get( $optOutId )->status || array() !== $repo->audit( $optOutId ) ) {
	throw new RuntimeException( 'Approval committed after MCP opt-out.' );
}
echo "Fix storage case passed.\n";
