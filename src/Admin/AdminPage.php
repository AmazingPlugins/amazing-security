<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertSettingsRenderer;
use AmazingPlugins\Security\Content\WordPressContentService;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Firewall\FirewallStatusRenderer;
use AmazingPlugins\Security\Firewall\ObservationStore;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\WordPressLoginSettings;
use AmazingPlugins\Security\Login\WordPressRateCounterStore;
use AmazingPlugins\Security\Login\WordPressTotpStore;
use AmazingPlugins\Security\Mcp\McpPreferences;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;

final class AdminPage {
	public function register(): void {
		$hook = add_menu_page( __( 'Amazing Security', 'amazing-security' ), __( 'Amazing Security', 'amazing-security' ), 'manage_options', 'amazing-security', array( $this, 'render' ), 'dashicons-shield-alt', 81 );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current_hook ) use ( $hook ): void {
				if ( $hook === $current_hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.8' );
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
		echo '<label class="amsec-header-consent"><input type="checkbox" name="amsec_header_consent" value="1"> ' . esc_html__( "Request this site's homepage and read its response headers.", 'amazing-security' ) . '</label>';
		submit_button( __( 'Run local checks', 'amazing-security' ), 'primary', 'submit', false );
		echo '</form></header>';
		$contentScanId = '';
		try {
			$active = ( new WordPressContentService() )->create()->status()['active'] ?? null;
			if ( is_array( $active ) && empty( $active['finished'] ) && is_string( $active['scan_id'] ?? null ) && 1 === preg_match( '/^[a-f0-9]{32}$/D', $active['scan_id'] ) ) {
				$contentScanId = $active['scan_id'];
			}
		} catch ( \Throwable ) {
			$contentScanId = '';
		}
		$integrityScanId = '';
		if ( null !== $progress && ! $progress->finished && 1 === preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $progress->cursor->scanId ) ) {
			$integrityScanId = $progress->cursor->scanId;
		}
		$fileScanId = '';
		if ( null !== $fileProgress && ! $fileProgress->finished && 1 === preg_match( '/^[a-zA-Z0-9-]{1,80}$/D', $fileProgress->cursor->scanId ) ) {
			$fileScanId = $fileProgress->cursor->scanId;
		}
		$this->startList( $run?->results ?? null, $integrityScanId, $contentScanId, $fileScanId );
		// ScheduleStatusRenderer escapes dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new ScheduleStatusRenderer() )->render( ( new LocalSchedule( $options ) )->status( time() ) );
		// ScheduleStatusRenderer escapes dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new ScheduleStatusRenderer() )->renderSuite( ( new SuiteCycle( $options ) )->status( time() ) );
		echo '<section class="amsec-overview" aria-labelledby="amsec-overview-title"><h2 id="amsec-overview-title">Security overview</h2><div class="amsec-ledger">';
		$this->ledgerRow( 'Local hardening', $run?->results ?? null, $run?->finishedAt?->format( 'Y-m-d H:i:s' ), '#amsec-hardening' );
		$this->ledgerRow( 'Release files', $integrity?->results ?? null, $integrity?->finishedAt?->format( 'Y-m-d H:i:s' ), '#amsec-integrity' );
		echo '<div class="amsec-ledger-row"><span class="amsec-ledger-name">Suspicious files</span><strong>' . esc_html( $fileState ) . '</strong><span class="amsec-ledger-date">' . esc_html( $fileCompleted?->finishedAt->format( 'Y-m-d H:i:s' ) ?? 'No completed check' ) . '</span><span class="amsec-ledger-coverage">' . esc_html( null === $fileProgress ? ( null === $fileCompleted ? 'No check yet' : (string) $fileCompleted->processed . ' files seen' ) : (string) $fileProgress->cursor->processed . ' files seen' ) . '</span><a href="#amsec-file-scan">Details</a></div>';
		$this->ledgerRow( 'Vulnerabilities', $direct ? $vulnCurrent?->results : null, $vulnCurrent?->snapshotGeneratedAt, '#amsec-vulnerabilities' );
		echo '</div>';
		$this->attentionList( $run?->results ?? array(), $integrity?->results ?? array(), $direct ? $vulnCurrent?->results ?? array() : array(), $fileAttention );
		echo '</section>';
		// FirewallStatusRenderer escapes dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new FirewallStatusRenderer() )->render( ( new ObservationStore( $options ) )->summary() );
		$alertState = ( new AlertDelivery( $options, static fn(): bool => false, '', '' ) )->status();
		// AlertSettingsRenderer escapes dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new AlertSettingsRenderer() )->render( '0' !== $options->get( 'amsec_alerts_enabled' ), $alertState, admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_alert_settings' ) );
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
			submit_button( __( 'Run integrity scan', 'amazing-security' ) );
			echo '</form>';
		} else {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_integrity_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $progress->cursor->scanId ) . '">';
			wp_nonce_field( 'amazing_security_integrity_resume' );
			submit_button( __( 'Continue integrity scan', 'amazing-security' ) );
			echo '</form>';
		}
		// IntegrityReportRenderer escapes all dynamic values.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new IntegrityReportRenderer() )->render( $integrity, $progress );
		echo '<div class="amsec-file-actionbar"><form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post">';
		if ( null === $fileProgress || $fileProgress->finished ) {
			echo '<input type="hidden" name="action" value="amazing_security_file_scan_start">';
			wp_nonce_field( 'amazing_security_file_scan_start' );
			submit_button( __( 'Run file scan', 'amazing-security' ), 'primary', 'submit', false );
		} else {
			echo '<input type="hidden" name="action" value="amazing_security_file_scan_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $fileProgress->cursor->scanId ) . '">';
			wp_nonce_field( 'amazing_security_file_scan_resume' );
			submit_button( __( 'Continue file scan', 'amazing-security' ), 'primary', 'submit', false );
		}
		echo '</form></div>';
		// FileScanReportRenderer escapes dynamic values, including saved notes.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new FileScanReportRenderer( admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_file_scan_note' ), $fileStore->notes() ) )->render( $fileCompleted, $fileProgress, $fileHistory );
		if ( $direct ) {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_scan">';
			wp_nonce_field( 'amazing_security_vulnerability_scan' );
			submit_button( __( 'Check installed versions', 'amazing-security' ) );
			echo '</form>';
			$scanProgress = get_transient( 'amsec_vuln_progress' );
			if ( is_array( $scanProgress ) ) {
				$phase = 'provenance' === ( $scanProgress['phase'] ?? null ) ? 'Verifying local release files' : 'Checking published issues';
				echo '<p role="status">' . esc_html( $phase ) . ': ' . esc_html( (string) (int) ( $scanProgress['offset'] ?? 0 ) ) . ' of ' . esc_html( (string) (int) ( $scanProgress['total'] ?? 0 ) ) . ' packages processed. The next batch is scheduled.</p>';
			}
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_disable">';
			wp_nonce_field( 'amazing_security_vulnerability_disable' );
			submit_button( __( 'Turn off vulnerability checks', 'amazing-security' ), 'secondary' );
			echo '</form>';
		} else {
			echo '<section class="amsec-consent" aria-labelledby="amsec-consent-title"><h3 id="amsec-consent-title">Enable vulnerability checks</h3><p>This WordPress site will contact WPVulnerability directly for its core version and installed plugin and theme slugs. The provider can see this site’s request IP address and requested components. AmazingPlugins receives no inventory. Results are stored on this site. Read the <a href="https://www.wpvulnerability.com/privacy/" target="_blank" rel="noopener noreferrer">provider privacy policy</a> and <a href="https://www.wpvulnerability.com/license/" target="_blank" rel="noopener noreferrer">data license</a>.</p>';
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_enable">';
			wp_nonce_field( 'amazing_security_vulnerability_enable' );
			submit_button( __( 'Enable vulnerability checks', 'amazing-security' ) );
			echo '</form></section>';
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_clear">';
		wp_nonce_field( 'amazing_security_vulnerability_clear' );
		submit_button( __( 'Clear local vulnerability data', 'amazing-security' ), 'secondary' );
		echo '</form>';
		// VulnerabilityReportRenderer escapes every dynamic value before constructing markup.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new VulnerabilityReportRenderer() )->render( $vulnCurrent, $vulnStore->historical(), null, $direct );
		echo '</div>';
	}

	private function startList( ?array $results, string $integrityScanId = '', string $contentScanId = '', string $fileScanId = '' ): void {
		echo '<section class="amsec-overview" aria-labelledby="amsec-start-title"><h2 id="amsec-start-title">Start here</h2>';
		if ( null === $results ) {
			echo '<p>Run local checks. The first list is HTTPS, WordPress updates, the admin login, debug display, the theme and plugin editor, and login monitoring.</p>';
			$this->reportDownload();
			echo '</section>';
			return;
		}
		echo '<p>The first six rows stay in this order. Review means that row needs a look. Not run means that scan has not started. Continue means it started and still has work left. One pass does not mean the site is clean.</p>';
		$this->startItems( StartHere::rows( $results, StartHere::ORDER ), $integrityScanId, $contentScanId, $fileScanId );
		$later      = StartHere::rows( $results, StartHere::LATER );
		$review     = array();
		$notRun     = array();
		$unfinished = array();
		$unread     = array();
		$passing    = array();
		foreach ( $later as $result ) {
			$stored = is_string( $result->evidence['stored'] ?? null ) ? $result->evidence['stored'] : '';
			if ( 'none' === $stored ) {
				$notRun[] = $result;
			} elseif ( in_array( $stored, array( 'partial', 'running' ), true ) ) {
				$unfinished[] = $result;
			} elseif ( in_array( $result->state, array( 'warn', 'fail' ), true ) ) {
				$review[] = $result;
			} elseif ( 'pass' === $result->state ) {
				$passing[] = $result;
			} else {
				$unread[] = $result;
			}
		}
		echo '<h3 class="amsec-start-heading">Review these</h3>';
		if ( array() === $review ) {
			echo '<p>Nothing else in this list needs review.</p>';
		} else {
			$this->startItems( $review, $integrityScanId, $contentScanId, $fileScanId );
		}
		if ( array() !== $unfinished ) {
			echo '<h3 class="amsec-start-heading">Not finished</h3>';
			$this->startItems( $unfinished, $integrityScanId, $contentScanId, $fileScanId );
		}
		if ( array() !== $notRun ) {
			echo '<h3 class="amsec-start-heading">Not run yet</h3>';
			$this->startItems( $notRun, $integrityScanId, $contentScanId, $fileScanId );
		}
		if ( array() !== $unread ) {
			echo '<h3 class="amsec-start-heading">Could not check</h3>';
			$this->startItems( $unread, $integrityScanId, $contentScanId, $fileScanId );
		}
		if ( array() !== $passing ) {
			echo '<details class="amsec-start-done"><summary>Already in place (' . esc_html( (string) count( $passing ) ) . ')</summary>';
			$this->startItems( $passing, $integrityScanId, $contentScanId, $fileScanId );
			echo '</details>';
		}
		$this->reportDownload();
		echo '</section>';
	}

	/** @param array<int, mixed> $results */
	private function startItems( array $results, string $integrityScanId, string $contentScanId, string $fileScanId ): void {
		echo '<ul class="amsec-start">';
		foreach ( $results as $result ) {
			if ( ! $result instanceof CheckResult ) {
				continue;
			}
			$stored = is_string( $result->evidence['stored'] ?? null ) ? $result->evidence['stored'] : '';
			$tone   = match ( $stored ) {
				'none' => 'none',
				'partial', 'running' => 'partial',
				default => $result->state,
			};
			$badge = match ( $tone ) {
				'none' => 'Not run',
				'partial' => 'Continue',
				'warn', 'fail' => 'Review',
				'pass' => 'In place',
				default => 'Unknown',
			};
			echo '<li class="amsec-start-item" data-state="' . esc_attr( $tone ) . '"><span class="amsec-start-badge">' . esc_html( $badge ) . '</span><span class="amsec-start-copy"><strong>' . esc_html( StartHere::label( $result->checkId ) ) . '</strong> ' . esc_html( $result->summary ) . '</span>';
			$this->startControl( StartHere::control( $result ), $integrityScanId, $contentScanId, $fileScanId );
			echo '</li>';
		}
		echo '</ul>';
	}

	private function reportDownload(): void {
		echo '<form class="amsec-start-action" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_findings_report">';
		wp_nonce_field( 'amsec_findings_report' );
		echo '<button type="submit" class="button">Download findings</button></form>';
		echo '<p>The file is a starting list for a host. It is not a compliance report, and it does not start a new check.</p>';
	}

	/** @param array<string, string>|null $control */
	private function startControl( ?array $control, string $integrityScanId, string $contentScanId, string $fileScanId = '' ): void {
		if ( null === $control ) {
			return;
		}
		if ( isset( $control['screen'] ) && 1 === preg_match( '/^[a-z0-9-]+\\.php$/D', $control['screen'] ) ) {
			echo ' <a class="button" href="' . esc_url( admin_url( $control['screen'] ) ) . '">' . esc_html( $control['label'] ) . '</a>';
			return;
		}
		if ( isset( $control['page'] ) ) {
			echo ' <a class="button" href="' . esc_url( admin_url( 'admin.php?page=' . $control['page'] ) ) . '">' . esc_html( $control['label'] ) . '</a>';
			return;
		}
		if ( isset( $control['hash'] ) ) {
			echo ' <a class="button" href="#' . esc_attr( $control['hash'] ) . '">' . esc_html( $control['label'] ) . '</a>';
			return;
		}
		$scan   = $control['scan'] ?? '';
		$scanId = match ( $scan ) {
			'integrity' => $integrityScanId,
			'content' => $contentScanId,
			'files' => $fileScanId,
			default => '',
		};
		if ( '' !== $scan && '' === $scanId ) {
			$control = match ( $scan ) {
				'integrity' => array(
					'label'  => 'Run integrity scan',
					'action' => 'amazing_security_integrity_start',
					'nonce'  => 'amazing_security_integrity_start',
				),
				'files' => array(
					'label'  => 'Run file scan',
					'action' => 'amazing_security_file_scan_start',
					'nonce'  => 'amazing_security_file_scan_start',
				),
				default => array(
					'label' => 'Review content scan',
					'page'  => 'amsec-content',
				),
			};
			$this->startControl( $control, '', '', '' );
			return;
		}
		$nonce = $control['nonce'];
		if ( 'amsec_content_resume' === $nonce ) {
			$nonce .= '_' . $scanId;
		}
		echo '<form class="amsec-start-action" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="' . esc_attr( $control['action'] ) . '">';
		if ( isset( $control['operation'] ) ) {
			echo '<input type="hidden" name="operation" value="' . esc_attr( $control['operation'] ) . '"><input type="hidden" name="scan_id" value="' . esc_attr( $scanId ) . '">';
		} elseif ( '' !== $scanId ) {
			echo '<input type="hidden" name="scan_id" value="' . esc_attr( $scanId ) . '">';
		}
		wp_nonce_field( $nonce );
		echo '<button type="submit" class="button">' . esc_html( $control['label'] ) . '</button></form>';
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
