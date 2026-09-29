<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;
use AmazingPlugins\Security\Login\WordPressTotpStore;
use AmazingPlugins\Security\Mcp\McpPreferences;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;

final class AdminPage {
	public function register(): void {
		$hook = add_menu_page( 'Amazing Security', 'Amazing Security', 'manage_options', 'amazing-security', array( $this, 'render' ), 'dashicons-shield-alt', 81 );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current_hook ) use ( $hook ): void {
				if ( $hook === $current_hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' );
				}
			}
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$run           = ( new FindingsRepository() )->latest();
		$options       = new WordPressOptions();
		$store         = new WordPressIntegrityStore( $options );
		$progress      = $store->latestProgress();
		$integrity     = $store->latestCompleted();
		$fileStore     = new WordPressFileScanStore( $options );
		$fileProgress  = $fileStore->latestProgress();
		$fileCompleted = $fileStore->latestCompleted();
		$fileHistory   = $fileStore->historicalWarnings();
		$fileState     = null !== $fileProgress ? ( $fileProgress->cursor->partial ? 'Partial coverage' : ( $fileProgress->finished ? 'Scan finished' : 'In progress' ) ) : ( $fileCompleted?->partial ? 'Partial coverage' : ( $fileCompleted?->state ?? 'Not checked' ) );
		$fileAttention = array_merge( $fileProgress?->cursor->findings ?? array(), $fileCompleted?->findings ?? array() );
		if ( $fileCompleted?->partial ) {
			foreach ( array_slice( $fileHistory, -5 ) as $oldWarning ) {
				$fileAttention = array_merge( $fileAttention, array_slice( $oldWarning->findings, 0, 3 ) );
			}
		}
		$vulnStore   = new WordPressVulnerabilityReportStore( $options );
		$vulnCurrent = $vulnStore->current();
		$direct      = ( new VulnerabilityPreferences( $options ) )->enabled();
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>Amazing Security</h1><p>See what needs attention and when each check last ran. These reports cover only the checks shown below.</p></div>';
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_scan">';
		wp_nonce_field( 'amazing_security_scan' );
		submit_button( 'Run local checks', 'primary', 'submit', false );
		echo '</form></header>';
		// ScheduleStatusRenderer escapes dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new ScheduleStatusRenderer() )->render( ( new LocalSchedule( $options ) )->status( time() ) );
		echo '<section class="amsec-overview" aria-labelledby="amsec-overview-title"><h2 id="amsec-overview-title">Security overview</h2><div class="amsec-ledger">';
		$this->ledgerRow( 'Local hardening', $run?->results ?? null, $run?->finishedAt?->format( 'Y-m-d H:i:s' ), '#amsec-hardening' );
		$this->ledgerRow( 'Release files', $integrity?->results ?? null, $integrity?->finishedAt?->format( 'Y-m-d H:i:s' ), '#amsec-integrity' );
		echo '<div class="amsec-ledger-row"><span class="amsec-ledger-name">Suspicious files</span><strong>' . esc_html( $fileState ) . '</strong><span class="amsec-ledger-date">' . esc_html( $fileCompleted?->finishedAt->format( 'Y-m-d H:i:s' ) ?? 'No completed check' ) . '</span><span class="amsec-ledger-coverage">' . esc_html( null === $fileProgress ? ( null === $fileCompleted ? 'No check yet' : (string) $fileCompleted->processed . ' files seen' ) : (string) $fileProgress->cursor->processed . ' files seen' ) . '</span><a href="#amsec-file-scan">Details</a></div>';
		$this->ledgerRow( 'Vulnerabilities', $direct ? $vulnCurrent?->results : null, $vulnCurrent?->snapshotGeneratedAt, '#amsec-vulnerabilities' );
		echo '</div>';
		$this->attentionList( $run?->results ?? array(), $integrity?->results ?? array(), $direct ? $vulnCurrent?->results ?? array() : array(), $fileAttention );
		echo '</section>';
		$loginSettings = new WordPressLoginSettings( $options );
		$loginStore    = new WordPressTotpStore( $GLOBALS['wpdb'] );
		try {
			$loginEnrolled = $loginStore->isEnrolled( get_current_user_id() );
		} catch ( \RuntimeException ) {
			$loginEnrolled = true;
			echo '<div class="notice notice-error"><p>Administrator verification status could not be read. Use the documented WP-CLI recovery route if sign-in is affected.</p></div>';
		}
		$rateSummary = ( new WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->summary( time() );
		$loginView   = new LoginView(
			admin_url( 'admin-post.php' ),
			array(
				'settings'   => wp_create_nonce( 'amsec_login_settings' ),
				'begin'      => wp_create_nonce( 'amsec_totp_begin' ),
				'disable'    => wp_create_nonce( 'amsec_totp_disable' ),
				'regenerate' => wp_create_nonce( 'amsec_totp_regenerate' ),
			),
			$loginSettings->rateMode(),
			$loginSettings->xmlRpcAuthDisabled(),
			$loginEnrolled,
			is_ssl(),
			wp_get_current_user()->user_login,
			$loginSettings->eraseOnUninstall(),
			$rateSummary
		);
		// LoginProtectionRenderer escapes all dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new LoginProtectionRenderer() )->render( $loginView );
		$mcpEnabled       = ( new McpPreferences( $options ) )->enabled();
		$adapterAvailable = function_exists( 'is_plugin_active' ) && is_plugin_active( 'mcp-adapter/mcp-adapter.php' );
		// McpSettingsRenderer escapes all dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new McpSettingsRenderer() )->render( $mcpEnabled, function_exists( 'wp_register_ability' ), $adapterAvailable, admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_mcp_settings' ) );
		// This flag selects a static message and does not change state or enter output.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error"><p>Scan could not be saved. The previous report is still shown.</p></div>';
		}
		// This flag selects a static error message only.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_integrity_error'] ) ) {
			echo '<div class="notice notice-error"><p>Integrity scan could not finish. The previous completed report remains available.</p></div>';
		}
		// This flag selects a static message only.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_file_scan_error'] ) ) {
			echo '<div class="notice notice-error"><p>File scan could not finish. The previous completed report remains available.</p></div>';
		}
		// This flag selects a static message and does not change state or enter output.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_vulnerability_error'] ) ) {
			echo '<div class="notice notice-error"><p>Vulnerability inventory could not be saved. The previous report remains available.</p></div>';
		}
		echo '<section aria-labelledby="amsec-hardening"><h2 id="amsec-hardening">Local hardening</h2>';
		// ReportRenderer escapes every dynamic value before constructing markup.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $run ? ( new ReportRenderer() )->render( $run ) : '<p>No scan has run yet.</p>';
		echo '</section>';
		if ( null === $progress || $progress->finished ) {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_integrity_start">';
			wp_nonce_field( 'amazing_security_integrity_start' );
			submit_button( 'Run integrity scan' );
			echo '</form>';
		} else {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_integrity_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $progress->cursor->scanId ) . '">';
			wp_nonce_field( 'amazing_security_integrity_resume' );
			submit_button( 'Continue integrity scan' );
			echo '</form>';
		}
		// IntegrityReportRenderer escapes all dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new IntegrityReportRenderer() )->render( $integrity, $progress );
		echo '<div class="amsec-file-actionbar"><form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post">';
		if ( null === $fileProgress || $fileProgress->finished ) {
			echo '<input type="hidden" name="action" value="amazing_security_file_scan_start">';
			wp_nonce_field( 'amazing_security_file_scan_start' );
			submit_button( 'Run file scan', 'primary', 'submit', false );
		} else {
			echo '<input type="hidden" name="action" value="amazing_security_file_scan_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $fileProgress->cursor->scanId ) . '">';
			wp_nonce_field( 'amazing_security_file_scan_resume' );
			submit_button( 'Continue file scan', 'primary', 'submit', false );
		}
		echo '</form></div>';
		// FileScanReportRenderer escapes dynamic values, including saved notes.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new FileScanReportRenderer( admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_file_scan_note' ), $fileStore->notes() ) )->render( $fileCompleted, $fileProgress, $fileHistory );
		if ( $direct ) {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_scan">';
			wp_nonce_field( 'amazing_security_vulnerability_scan' );
			submit_button( 'Check installed versions' );
			echo '</form>';
			$scanProgress = get_transient( 'amsec_vuln_progress' );
			if ( is_array( $scanProgress ) ) {
				$phase = 'provenance' === ( $scanProgress['phase'] ?? null ) ? 'Verifying local release files' : 'Checking published issues';
				echo '<p role="status">' . esc_html( $phase ) . ': ' . esc_html( (string) (int) ( $scanProgress['offset'] ?? 0 ) ) . ' of ' . esc_html( (string) (int) ( $scanProgress['total'] ?? 0 ) ) . ' packages processed. The next batch is scheduled.</p>';
			}
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_disable">';
			wp_nonce_field( 'amazing_security_vulnerability_disable' );
			submit_button( 'Turn off vulnerability checks', 'secondary' );
			echo '</form>';
		} else {
			echo '<section class="amsec-consent" aria-labelledby="amsec-consent-title"><h3 id="amsec-consent-title">Enable vulnerability checks</h3><p>This WordPress site will contact WPVulnerability directly for its core version and installed plugin and theme slugs. The provider can see this site’s request IP address and requested components. AmazingPlugins receives no inventory. Results are stored on this site. Read the <a href="https://www.wpvulnerability.com/privacy/" target="_blank" rel="noopener noreferrer">provider privacy policy</a> and <a href="https://www.wpvulnerability.com/license/" target="_blank" rel="noopener noreferrer">data license</a>.</p>';
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_enable">';
			wp_nonce_field( 'amazing_security_vulnerability_enable' );
			submit_button( 'Enable vulnerability checks' );
			echo '</form></section>';
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_clear">';
		wp_nonce_field( 'amazing_security_vulnerability_clear' );
		submit_button( 'Clear local vulnerability data', 'secondary' );
		echo '</form>';
		// VulnerabilityReportRenderer escapes every dynamic value before constructing markup.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new VulnerabilityReportRenderer() )->render( $vulnCurrent, $vulnStore->historical(), null, $direct );
		echo '</div>';
	}

	private function ledgerRow( string $label, ?array $results, ?string $checkedAt, string $href ): void {
		$state = 'Not checked';
		if ( null !== $results ) {
			$states = array_map( static fn ( $row ): string => $row->state, $results );
			$state  = array_intersect( $states, array( 'warn', 'fail' ) ) ? 'Needs attention' : ( array_intersect( $states, array( 'unknown', 'inconclusive' ) ) ? 'Could not check everything' : 'Checked' );
		}
		$coverage = null === $results ? 'No check yet' : count( array_filter( $results, static fn ( $row ): bool => ! in_array( $row->state, array( 'unknown', 'inconclusive' ), true ) ) ) . ' of ' . count( $results ) . ' findings checked';
		echo '<div class="amsec-ledger-row"><span class="amsec-ledger-name">' . esc_html( $label ) . '</span><strong>' . esc_html( $state ) . '</strong><span class="amsec-ledger-date">' . esc_html( $checkedAt ?? 'No completed check' ) . '</span><span class="amsec-ledger-coverage">' . esc_html( $coverage ) . '</span><a href="' . esc_url( $href ) . '">Details</a></div>';
	}

	private function attentionList( array $hardening, array $integrity, array $vulnerabilities, array $files = array() ): void {
		$items = array();
		foreach ( array(
			'#amsec-hardening'       => $hardening,
			'#amsec-integrity'       => $integrity,
			'#amsec-vulnerabilities' => $vulnerabilities,
		) as $href => $results ) {
			foreach ( $results as $result ) {
				if ( in_array( $result->state, array( 'warn', 'fail' ), true ) ) {
					$items[] = array(
						'href'    => $href,
						'summary' => $result->summary,
						'state'   => $result->state,
					);
				}
			}
		}
		$seenFiles = array();
		foreach ( $files as $finding ) {
			if ( 'warn' === ( $finding['state'] ?? '' ) ) {
				$key = (string) ( $finding['package'] ?? '' ) . ':' . (string) ( $finding['path'] ?? '' ) . ':' . (string) ( $finding['kind'] ?? '' );
				if ( isset( $seenFiles[ $key ] ) ) {
					continue;
				}
				$seenFiles[ $key ] = true;
				$items[]           = array(
					'href'    => '#amsec-file-scan',
					'summary' => ( 'suspected' === ( $finding['kind'] ?? '' ) ? 'Suspected code' : 'Review file' ) . ': ' . (string) ( $finding['path'] ?? '' ),
					'state'   => 'warn',
				);
			}
		}
		echo '<div class="amsec-attention"><h3>Needs attention</h3>';
		if ( array() === $items ) {
			echo '<p>No attention findings in completed checks. Review unknown coverage below.</p></div>';
			return;
		}
		usort( $items, static fn ( array $a, array $b ): int => ( 'fail' === $a['state'] ? 0 : 1 ) <=> ( 'fail' === $b['state'] ? 0 : 1 ) );
		echo '<p>' . esc_html( (string) count( $items ) ) . ' findings need review.</p><ul>';
		foreach ( array_slice( $items, 0, 3 ) as $item ) {
			echo '<li><a href="' . esc_url( $item['href'] ) . '">' . esc_html( $item['summary'] ) . '</a></li>';
		}
		echo '</ul></div>';
	}
}
