<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Rules;

defined( 'ABSPATH' ) || exit;

final class RulePage {
	public function register(): void {
		$hook = add_submenu_page( 'ironlatch-security-scanner', __( 'Rule information', 'ironlatch-security-scanner' ), __( 'Rule information', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-rules', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'ironlatch-security-scanner-admin', plugins_url( 'assets/admin.css', IRONLATCH_SECURITY_SCANNER_FILE ), array(), '0.1.0' );
				}}
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$packs = ( new RuleCatalog( IRONLATCH_SECURITY_SCANNER_DIR ) )->status( time() );
		echo '<div class="wrap ironlatch-security-scanner-admin"><header class="ironlatch-header"><div><h1>' . esc_html__( 'Rule information', 'ironlatch-security-scanner' ) . '</h1><p>' . esc_html__( 'Versions and review records for the local patterns installed with this plugin.', 'ironlatch-security-scanner' ) . '</p></div></header><section class="ironlatch-overview"><h2>' . esc_html__( 'What the review date means', 'ironlatch-security-scanner' ) . '</h2><p>' . esc_html__( 'The date records bundled metadata review. It does not establish current threat coverage, a maintained malware feed or a clean site. After 90 days, metadata review is marked overdue. Missing, changed or invalid source records are unknown. Scanning behavior is unchanged by these advisory labels.', 'ironlatch-security-scanner' ) . '</p><p>' . esc_html__( 'Source hashes are compared with a record in the same plugin package. This can reveal package drift, but it is not independent proof of authenticity. Existing findings retain their recorded rule version; installing another version does not refresh old scans.', 'ironlatch-security-scanner' ) . '</p></section>';
		foreach ( $packs as $pack ) {
			$label = match ( $pack['status'] ) {
				'recent'=>__( 'Metadata recently reviewed', 'ironlatch-security-scanner' ), 'overdue'=>__( 'Metadata review overdue', 'ironlatch-security-scanner' ), default=>__( 'Package record unknown', 'ironlatch-security-scanner' )};
			echo '<section class="ironlatch-file-scan"><div class="ironlatch-file-heading"><h2>' . esc_html( $pack['label'] ) . '</h2><span class="ironlatch-file-rule-age">' . sprintf(
				/* translators: %s: version of the installed rule pack. */
				esc_html__( 'Installed version %s', 'ironlatch-security-scanner' ),
				esc_html( $pack['version'] )
			) . '</span></div><div class="ironlatch-file-status" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . sprintf(
				/* translators: %s: number of local patterns in the rule pack. */
				esc_html__( '%s local patterns', 'ironlatch-security-scanner' ),
				esc_html( (string) count( $pack['ids'] ) )
			) . '</span></div><p>' . esc_html( $pack['scope'] ) . '</p><dl><dt>' . esc_html__( 'Metadata reviewed UTC', 'ironlatch-security-scanner' ) . '</dt><dd>' . esc_html( '' === $pack['reviewed_at'] ? __( 'Unknown', 'ironlatch-security-scanner' ) : $pack['reviewed_at'] ) . '</dd><dt>' . esc_html__( 'Origin and license', 'ironlatch-security-scanner' ) . '</dt><dd>' . esc_html( $pack['origin'] . '; ' . $pack['license'] ) . '</dd><dt>' . esc_html__( 'Review responsibility', 'ironlatch-security-scanner' ) . '</dt><dd>' . esc_html( $pack['owner'] ) . '</dd></dl><details><summary>' . esc_html__( 'Pattern IDs and development references', 'ironlatch-security-scanner' ) . '</summary><p>' . esc_html( implode( ', ', $pack['ids'] ) ) . '</p><p>' . esc_html__( 'Source:', 'ironlatch-security-scanner' ) . ' ' . esc_html( implode( ', ', $pack['files'] ) ) . '<br>' . esc_html__( 'Regression reference:', 'ironlatch-security-scanner' ) . ' ' . esc_html( $pack['fixtures'] ) . '. ' . esc_html__( 'Test fixtures belong to the development repository and are not included in the install ZIP.', 'ironlatch-security-scanner' ) . '</p></details></section>';
		}
		echo '<section class="ironlatch-file-scan"><h2>' . esc_html__( 'Updates and recovery', 'ironlatch-security-scanner' ) . '</h2><p>' . esc_html__( 'Rules are bundled with plugin releases. No rule code is downloaded or replaced by this page. Update through the normal WordPress plugin process once a tested release is available. To recover from an update, the host administrator must back up the database and install an exact previously tested plugin ZIP with compatible storage formats, then restart scans. A downgrade can remove protections or reintroduce bugs. Retained findings remain historical.', 'ironlatch-security-scanner' ) . '</p><p>' . esc_html__( 'There is no separate signature feed. New rules arrive with plugin updates.', 'ironlatch-security-scanner' ) . '</p></section></div>';
	}
}
