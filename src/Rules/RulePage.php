<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Rules;

final class RulePage {
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', 'Rule information', 'Rule information', 'manage_options', 'amsec-rules', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}}
		);
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
		$packs = ( new RuleCatalog( dirname( AMAZING_SECURITY_FILE ) ) )->status( time() );
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Rule information</h1><p>Versions and review records for the local patterns installed with this plugin.</p></div></header><section class="amsec-overview"><h2>What the review date means</h2><p>The date records bundled metadata review. It does not establish current threat coverage, a maintained malware feed or a clean site. After 90 days, metadata review is marked overdue. Missing, changed or invalid source records are unknown. Scanning behavior is unchanged by these advisory labels.</p><p>Source hashes are compared with a record in the same plugin package. This can reveal package drift, but it is not independent proof of authenticity. Existing findings retain their recorded rule version; installing another version does not refresh old scans.</p></section>';
		foreach ( $packs as $pack ) {
			$label = match ( $pack['status'] ) {
				'recent'=>'Metadata recently reviewed', 'overdue'=>'Metadata review overdue', default=>'Package record unknown'};
			echo '<section class="amsec-file-scan"><div class="amsec-file-heading"><h2>' . esc_html( $pack['label'] ) . '</h2><span class="amsec-file-rule-age">Installed version ' . esc_html( $pack['version'] ) . '</span></div><div class="amsec-file-status" role="status"><strong>' . esc_html( $label ) . '</strong><span>' . esc_html( (string) count( $pack['ids'] ) ) . ' local patterns</span></div><p>' . esc_html( $pack['scope'] ) . '</p><dl><dt>Metadata reviewed UTC</dt><dd>' . esc_html( '' === $pack['reviewed_at'] ? 'Unknown' : $pack['reviewed_at'] ) . '</dd><dt>Origin and license</dt><dd>' . esc_html( $pack['origin'] . '; ' . $pack['license'] ) . '</dd><dt>Review responsibility</dt><dd>' . esc_html( $pack['owner'] ) . '</dd></dl><details><summary>Pattern IDs and development references</summary><p>' . esc_html( implode( ', ', $pack['ids'] ) ) . '</p><p>Source: ' . esc_html( implode( ', ', $pack['files'] ) ) . '<br>Regression reference: ' . esc_html( $pack['fixtures'] ) . '. Test fixtures belong to the development repository and are not included in the install ZIP.</p></details></section>';
		}
		echo '<section class="amsec-file-scan"><h2>Updates and recovery</h2><p>Rules are bundled with plugin releases. No rule code is downloaded or replaced by this page. Update through the normal WordPress plugin process once a tested release is available. To recover from an update, the host administrator must back up the database and install an exact previously tested plugin ZIP with compatible storage formats, then restart scans. A downgrade can remove protections or reintroduce bugs. Retained findings remain historical.</p><p>Broader independent detection tests and a staffed maintenance process remain requirements before public release.</p></section></div>';
	}
}
