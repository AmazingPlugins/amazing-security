<?php

// Run with: AMSEC_CASE=disabled|enabled|editor|anonymous|optout wp eval-file ... --user=admin.
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

$case  = getenv( 'AMSEC_CASE' );
$names = array( 'list-findings', 'get-finding', 'start-scan', 'get-scan', 'propose-fix', 'get-fix-status' );
if ( ! function_exists( 'wp_get_ability' ) ) {
	throw new RuntimeException( 'Abilities API unavailable on supported MCP fixture.' );
}
foreach ( $names as $name ) {
	if ( ! wp_get_ability( 'amsec-security-scanner/' . $name ) ) {
		throw new RuntimeException( 'Missing AmSec Security Scanner ability: ' . $name );
	}
}
$list = wp_get_ability( 'amsec-security-scanner/list-findings' );
if ( 'disabled' === $case ) {
	if ( true === ( $list->get_meta()['mcp']['public'] ?? null ) || ! is_wp_error( $list->execute( array() ) ) ) {
		throw new RuntimeException( 'Disabled MCP still exposed report.' );
	}
} elseif ( 'enabled' === $case ) {
	if ( true !== ( $list->get_meta()['mcp']['public'] ?? null ) ) {
		throw new RuntimeException( 'Enabled MCP was not exposed.' );
	}
	$page = $list->execute( array( 'limit' => 2 ) );
	if ( is_wp_error( $page ) || ! isset( $page['findings'], $page['schema_version'] ) || count( $page['findings'] ) > 2 ) {
		throw new RuntimeException( 'Invalid list result.' );
	}
	delete_option( 'amsec_security_scanner_mcp_scan_last_' . get_current_user_id() );
	update_option( 'amsec_login_rate_mode', 'off', false );
	$scan = wp_get_ability( 'amsec-security-scanner/start-scan' )->execute( array( 'type' => 'hardening' ) );
	if ( is_wp_error( $scan ) || 'complete' !== ( $scan['state'] ?? null ) ) {
		throw new RuntimeException( 'Hardening scan could not start.' );
	}
	$detail = wp_get_ability( 'amsec-security-scanner/get-scan' )->execute( array( 'scan_id' => $scan['scan_id'] ) );
	if ( is_wp_error( $detail ) || 'complete' !== ( $detail['state'] ?? null ) ) {
		throw new RuntimeException( 'Saved scan could not be read.' );
	}
	$page    = $list->execute( array( 'limit' => 1 ) );
	$finding = wp_get_ability( 'amsec-security-scanner/get-finding' )->execute( array( 'finding_id' => $page['findings'][0]['id'] ) );
	if ( is_wp_error( $finding ) || 'found' !== ( $finding['state'] ?? null ) ) {
		throw new RuntimeException( 'Saved finding could not be read.' );
	}
	$again = wp_get_ability( 'amsec-security-scanner/start-scan' )->execute( array( 'type' => 'hardening' ) );
	if ( is_wp_error( $again ) || 'cooldown' !== ( $again['state'] ?? null ) ) {
		throw new RuntimeException( 'MCP scan cooldown failed.' );
	}
	$fixFinding = substr( hash( 'sha256', 'hardening:login-rate-mode' ), 0, 32 );
	$proposal   = wp_get_ability( 'amsec-security-scanner/propose-fix' )->execute(
		array(
			'finding_id' => $fixFinding,
			'recipe_id'  => 'login-rate-observe',
		)
	);
	if ( is_wp_error( $proposal ) || 'pending' !== ( $proposal['state'] ?? null ) || 'off' !== get_option( 'amsec_login_rate_mode' ) ) {
		throw new RuntimeException( 'MCP proposal mutated or was unavailable.' );
	}
	$status = wp_get_ability( 'amsec-security-scanner/get-fix-status' )->execute( array( 'proposal_id' => $proposal['proposal_id'] ) );
	if ( is_wp_error( $status ) || 'pending' !== ( $status['state'] ?? null ) ) {
		throw new RuntimeException( 'MCP fix status was not readable.' );
	}
} elseif ( 'editor' === $case || 'anonymous' === $case ) {
	wp_set_current_user( 'editor' === $case ? 2 : 0 );
	if ( ! is_wp_error( $list->execute( array() ) ) || ! is_wp_error( wp_get_ability( 'amsec-security-scanner/start-scan' )->execute( array( 'type' => 'hardening' ) ) ) ) {
		throw new RuntimeException( 'Low-privilege caller accessed MCP.' );
	}
	if ( ! is_wp_error(
		wp_get_ability( 'amsec-security-scanner/propose-fix' )->execute(
			array(
				'finding_id' => substr( hash( 'sha256', 'hardening:login-rate-mode' ), 0, 32 ),
				'recipe_id'  => 'login-rate-observe',
			)
		)
	) ) {
		throw new RuntimeException( 'Low-privilege caller proposed a fix.' );
	}
} elseif ( 'optout' === $case ) {
	( new McpPreferences( new WordPressOptions() ) )->setEnabled( false );
	if ( ! is_wp_error( $list->execute( array() ) ) ) {
		throw new RuntimeException( 'Known ability still executed after opt-out.' );
	}
	if ( ! is_wp_error(
		wp_get_ability( 'amsec-security-scanner/propose-fix' )->execute(
			array(
				'finding_id' => substr( hash( 'sha256', 'hardening:login-rate-mode' ), 0, 32 ),
				'recipe_id'  => 'login-rate-observe',
			)
		)
	) ) {
		throw new RuntimeException( 'Fix proposal still executed after opt-out.' );
	}
} else {
	throw new RuntimeException( 'Unknown test case.' );
}
echo 'MCP ability case passed: ' . $case . PHP_EOL;
