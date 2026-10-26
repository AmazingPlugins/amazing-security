<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertSettingsRenderer;
use AmazingPlugins\Security\Content\WordPressContentService;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Scan\LocalCodeScan;
use AmazingPlugins\Security\FileScan\FileScanStep;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Findings\SiteRisk;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Login\RequiredTotpPage;
use AmazingPlugins\Security\Free\Guide\Score;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use AmazingPlugins\Security\Vulnerabilities\ExploitedList;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;

final class AdminPage {
	public function register(): void {
		add_menu_page( __( 'AmazingPlugins Security Scanner', 'amazingplugins-security-scanner' ), __( 'Security Scanner', 'amazingplugins-security-scanner' ), 'manage_options', 'amazing-security', array( $this, 'render' ), 'dashicons-shield-alt', 81 );
		add_action( 'admin_menu', array( new FilesPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new FollowUpPages(), 'register' ), 20 );
		add_action( 'admin_menu', array( new RecordsPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new ToolIndex(), 'register' ), 20 );
		add_action( 'admin_menu', array( StartPanel::class, 'register' ), 20 );
		add_action( 'admin_menu', array( new ReviewPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new UploadsRulePage(), 'register' ), 20 );
		add_action( 'admin_menu', array( Submenu::class, 'trim' ), 999 );
		Brand::boot();
	}

	private function renderFirstScan(): void {
		echo '<div class="wrap amazing-security-admin amsec-scan amsec-scan-first"><div class="amsec-stage">';
		echo '<h1 class="screen-reader-text">' . esc_html__( 'Scan', 'amazingplugins-security-scanner' ) . '</h1>';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice after a failed scan redirect.
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error" data-amsec-scan-error><p>' . esc_html__( 'Scan could not be saved.', 'amazingplugins-security-scanner' ) . '</p></div>';
		}
		$this->scanForm( __( 'Scan', 'amazingplugins-security-scanner' ) );
		echo '</div></div>';
	}

	/**
	 * @param array<int, mixed>|null $results
	 */
	private function scanForm( string $label, bool $rescan = false ): void {
		echo '<form class="amsec-scan-form' . ( $rescan ? ' amsec-rescan-center' : '' ) . '" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post">';
		echo '<input type="hidden" name="action" value="amazing_security_scan">';
		wp_nonce_field( 'amazing_security_scan' );
		echo '<button type="submit" class="amsec-scan-button' . ( $rescan ? ' amsec-rescan-button' : '' ) . '">' . esc_html( $label ) . '</button>';
		echo '<div class="amsec-scan-progress" hidden><p class="amsec-scan-status">' . esc_html__( 'Scanning', 'amazingplugins-security-scanner' ) . ' <span class="amsec-scan-percent" aria-hidden="true"></span></p>';
		echo '<p class="amsec-scan-step"></p>';
		echo '<div class="amsec-scan-track" role="progressbar" aria-label="' . esc_attr__( 'Scan progress', 'amazingplugins-security-scanner' ) . '" aria-valuemin="0" aria-valuemax="100"><span class="amsec-scan-fill"></span></div>';
		echo '<p><button type="button" class="button amsec-scan-stop">' . esc_html__( 'Stop', 'amazingplugins-security-scanner' ) . '</button></p>';
		echo '<ol class="amsec-scan-list" aria-label="' . esc_attr__( 'Checks in this scan', 'amazingplugins-security-scanner' ) . '"></ol></div>';
		echo '</form>';
	}

	/**
	 * @param array<int, mixed> $results
	 * @return array{success: int, fail: int, critical: int, warn: int, recommended: int}
	 */
	private function scanCounts( array $results ): array {
		$counts = array(
			'success'     => 0,
			'fail'        => 0,
			'critical'    => 0,
			'warn'        => 0,
			'recommended' => 0,
		);
		foreach ( $results as $result ) {
			if ( ! $result instanceof CheckResult ) {
				continue;
			}
			$bucket = match ( self::statusOf( $result ) ) {
				'success' => 'success',
				'error' => 'fail',
				'critical' => 'critical',
				'warning' => 'warn',
				default => 'recommended',
			};
			++$counts[ $bucket ];
		}
		return $counts;
	}

	public static function statusOf( CheckResult $result ): string {
		$stored = is_string( $result->evidence['stored'] ?? null ) ? $result->evidence['stored'] : '';
		if ( in_array( $stored, array( 'none', 'partial', 'running' ), true ) ) {
			return 'recommended';
		}
		return match ( $result->state ) {
			'pass' => 'success',
			'fail' => 'error',
			'critical' => 'critical',
			'warn' => 'warning',
			default => 'recommended',
		};
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$run = ( new FindingsRepository() )->latest();
		if ( null === $run ) {
			$this->renderFirstScan();
			return;
		}
		echo '<div class="wrap amazing-security-admin amsec-scan"><h1 class="screen-reader-text">' . esc_html__( 'Scan', 'amazingplugins-security-scanner' ) . '</h1>';
		$this->scanForm( __( 'Rescan', 'amazingplugins-security-scanner' ), true );
		list( $integrityScanId, $contentScanId, $fileScanId ) = $this->scanIds();
		// These flags select a static message only.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Scan could not be saved. The previous report is still shown.', 'amazingplugins-security-scanner' ) . '</p></div>';
		}
		$category = $this->requestedCategory( $run->results );
		$this->categoryNav( $category, $this->scanCounts( $run->results ) );
		$this->statusList( $category, $run->results, $integrityScanId, $contentScanId, $fileScanId );
		echo '</div>';
	}

	/**
	 * Every result from the latest scan that is not a success, most serious first, with the same actions as the Scan page.
	 */
	public function recommendations(): void {
		$off = StartPanel::offRows();
		$run = ( new FindingsRepository() )->latest();
		if ( null === $run ) {
			echo '<p>' . esc_html__( 'Recommendations come from the scan. Run it once and this page fills in.', 'amazingplugins-security-scanner' ) . '</p>';
			$this->scanForm( __( 'Scan', 'amazingplugins-security-scanner' ) );
			StartPanel::protections( $off );
			StartPanel::incident();
			return;
		}
		list( $integrityScanId, $contentScanId, $fileScanId ) = $this->scanIds();
		$groups = array(
			'fix'         => array( __( 'Fix first', 'amazingplugins-security-scanner' ), array( 'critical', 'error' ), 'is-critical' ),
			'review'      => array( __( 'Review', 'amazingplugins-security-scanner' ), array( 'warning' ), 'is-warning' ),
			'recommended' => array( __( 'Recommended', 'amazingplugins-security-scanner' ), array( 'recommended' ), 'is-recommended' ),
		);
		$total  = 0;
		$byKey  = array();
		foreach ( $groups as $key => $group ) {
			$rows = array();
			foreach ( $run->results as $result ) {
				if ( $result instanceof CheckResult && in_array( self::statusOf( $result ), $group[1], true ) ) {
					$rows[] = $result;
				}
			}
			$byKey[ $key ] = $this->ranked( $rows );
			$total        += count( $rows );
		}
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: number of items, 2: date and time of the last scan. */
				_n( '%1$s item from the scan on %2$s needs attention, most serious first.', '%1$s items from the scan on %2$s need attention, most serious first.', $total, 'amazingplugins-security-scanner' ),
				(string) $total,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $run->finishedAt->getTimestamp() )
			)
		) . ' <a class="button" href="' . esc_url( admin_url( 'admin.php?page=amazing-security' ) ) . '">' . esc_html__( 'Scan again', 'amazingplugins-security-scanner' ) . '</a></p>';
		$tabs = array( 'overview' => array( __( 'Overview', 'amazingplugins-security-scanner' ), null, '' ) );
		foreach ( $groups as $key => $group ) {
			$tabs[ $key ] = array( $group[0], count( $byKey[ $key ] ), $group[2] );
		}
		$tabs['off'] = array( __( 'Turned off', 'amazingplugins-security-scanner' ), count( $off ), 'is-error' );
		$raw         = isset( $_GET['amsec_tab'] ) ? sanitize_key( wp_unslash( $_GET['amsec_tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Read-only view switch.
		$current     = isset( $tabs[ $raw ] ) ? $raw : 'overview';
		echo '<nav class="amsec-cats" aria-label="' . esc_attr__( 'Recommendation groups', 'amazingplugins-security-scanner' ) . '">';
		foreach ( $tabs as $slug => $tab ) {
			$url = add_query_arg(
				array(
					'page'      => 'amsec-recommendations',
					'amsec_tab' => $slug,
				),
				admin_url( 'admin.php' )
			);
			echo '<a class="' . esc_attr( $tab[2] . ( $slug === $current ? ' is-current' : '' ) ) . '"' . ( $slug === $current ? ' aria-current="page"' : '' ) . ' href="' . esc_url( $url ) . '">' . esc_html( $tab[0] ) . ( null === $tab[1] ? '' : ' <span class="amsec-cat-count">' . esc_html( (string) $tab[1] ) . '</span>' ) . '</a>';
		}
		echo '</nav><div class="amsec-tab-panel">';
		if ( 'overview' === $current ) {
			$options  = new WordPressOptions();
			$packages = ( new VulnerabilityPreferences( $options ) )->enabled() ? ( new WordPressVulnerabilityReportStore( $options ) )->current()?->results : null;
			// SiteRiskCard escapes all dynamic values.
			echo wp_kses( SiteRiskCard::render( SiteRisk::rows( $run->results, $packages, SiteRiskCard::botModes(), time() - $run->finishedAt->getTimestamp() ) ), AdminHtml::allowed() );
			if ( 0 === $total ) {
				echo '<p>' . esc_html__( 'Nothing from the last scan needs attention. That does not prove the site is clean.', 'amazingplugins-security-scanner' ) . '</p>';
			}
			StartPanel::incident();
		} elseif ( 'off' === $current ) {
			StartPanel::protections( $off );
		} else {
			echo '<section class="amsec-overview" aria-labelledby="amsec-rec-' . esc_attr( $current ) . '"><h2 id="amsec-rec-' . esc_attr( $current ) . '">' . esc_html( $groups[ $current ][0] . ' (' . count( $byKey[ $current ] ) . ')' ) . '</h2>';
			if ( array() === $byKey[ $current ] ) {
				echo '<p>' . esc_html__( 'Nothing in this group.', 'amazingplugins-security-scanner' ) . '</p>';
			} else {
				$this->startItems( $byKey[ $current ], $integrityScanId, $contentScanId, $fileScanId );
			}
			echo '</section>';
		}
		echo '</div>';
	}

	/**
	 * @param list<CheckResult> $rows
	 * @return list<CheckResult>
	 */
	private function ranked( array $rows ): array {
		$ranked = array_flip( array_merge( StartHere::ORDER, StartHere::LATER ) );
		usort( $rows, static fn ( CheckResult $left, CheckResult $right ): int => ( $ranked[ $left->checkId ] ?? 1000 ) <=> ( $ranked[ $right->checkId ] ?? 1000 ) );
		return $rows;
	}

	/** @return array{0: string, 1: string, 2: string} Integrity, content and file scan IDs that can be resumed. */
	private function scanIds(): array {
		$options       = new WordPressOptions();
		$progress      = ( new WordPressIntegrityStore( $options ) )->latestProgress();
		$fileProgress  = ( new WordPressFileScanStore( $options ) )->latestProgress();
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
		return array( $integrityScanId, $contentScanId, $fileScanId );
	}

	public function renderSection( string $section ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$options      = new WordPressOptions();
		$store        = new WordPressIntegrityStore( $options );
		$progress     = $store->latestProgress();
		$integrity    = $store->latestCompleted();
		$fileStore    = new WordPressFileScanStore( $options );
		$fileProgress = $fileStore->latestProgress();
		$fileDone     = $fileStore->latestCompleted();
		$fileHistory  = $fileStore->historicalWarnings();
		$vulnStore    = new WordPressVulnerabilityReportStore( $options );
		$vulnCurrent  = $vulnStore->current();
		$direct       = ( new VulnerabilityPreferences( $options ) )->enabled();
		if ( 'files' === $section ) {
			$malware = LocalCodeScan::cursor();
			// Findings show once the pass is done; a running pass shows only how far it has got.
			if ( null !== $malware && ! $malware->finished ) {
				echo '<section class="amsec-file-scan" aria-labelledby="amsec-malware"><h2 id="amsec-malware">' . esc_html__( 'Malware scan', 'amazingplugins-security-scanner' ) . '</h2><div class="amsec-file-status amsec-file-status-progress" role="status"><strong>' . esc_html__( 'Scan in progress', 'amazingplugins-security-scanner' ) . '</strong><span>' . esc_html(
					sprintf(
						/* translators: %s: number of files checked so far. */
						_n( '%s file checked so far. Results appear here when the scan finishes.', '%s files checked so far. Results appear here when the scan finishes.', $malware->processed, 'amazingplugins-security-scanner' ),
						number_format_i18n( $malware->processed )
					)
				) . '</span></div></section>';
			} elseif ( null !== $malware ) {
				// FileScanReportRenderer escapes dynamic values.
				echo wp_kses( ( new FileScanReportRenderer( '', '', array(), __( 'Malware scan', 'amazingplugins-security-scanner' ), 'amsec-malware' ) )->render( null, new FileScanStep( $malware, $malware->finished ), array() ), AdminHtml::allowed() );
				echo '<p><a class="button" href="' . esc_url( admin_url( 'admin.php?page=amazing-security' ) ) . '">' . esc_html__( 'Scan again', 'amazingplugins-security-scanner' ) . '</a></p>';
			}
			// IntegrityReportRenderer escapes all dynamic values.
			echo wp_kses( ( new IntegrityReportRenderer() )->render( $integrity, $progress ), AdminHtml::allowed() );
			if ( null === $progress || $progress->finished ) {
				echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_integrity_start">';
				wp_nonce_field( 'amazing_security_integrity_start' );
				submit_button( __( 'Run integrity scan', 'amazingplugins-security-scanner' ), 'secondary' );
				echo '</form>';
			} else {
				echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_integrity_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $progress->cursor->scanId ) . '">';
				wp_nonce_field( 'amazing_security_integrity_resume' );
				submit_button( __( 'Continue integrity scan', 'amazingplugins-security-scanner' ), 'secondary' );
				echo '</form>';
			}
			// FileScanReportRenderer escapes dynamic values, including saved notes.
			echo wp_kses( ( new FileScanReportRenderer( admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_file_scan_note' ), $fileStore->notes() ) )->render( $fileDone, $fileProgress, $fileHistory ), AdminHtml::allowed() );
			echo '<div class="amsec-file-actionbar"><form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post">';
			if ( null === $fileProgress || $fileProgress->finished ) {
				echo '<input type="hidden" name="action" value="amazing_security_file_scan_start">';
				wp_nonce_field( 'amazing_security_file_scan_start' );
				submit_button( __( 'Run file scan', 'amazingplugins-security-scanner' ), 'primary', 'submit', false );
			} else {
				echo '<input type="hidden" name="action" value="amazing_security_file_scan_resume"><input type="hidden" name="scan_id" value="' . esc_attr( $fileProgress->cursor->scanId ) . '">';
				wp_nonce_field( 'amazing_security_file_scan_resume' );
				submit_button( __( 'Continue file scan', 'amazingplugins-security-scanner' ), 'primary', 'submit', false );
			}
			echo '</form></div>';
			return;
		}
		if ( 'vulnerabilities' === $section ) {
			$this->vulnerabilitySection( $direct, $vulnStore, $vulnCurrent );
			return;
		}
		if ( 'schedule' === $section ) {
			// ScheduleStatusRenderer escapes dynamic values.
			echo wp_kses( ( new ScheduleStatusRenderer() )->render( ( new LocalSchedule( $options ) )->status( time() ) ), AdminHtml::allowed() );
			echo wp_kses( ( new ScheduleStatusRenderer() )->renderSuite( ( new SuiteCycle( $options ) )->status( time() ) ), AdminHtml::allowed() );
			return;
		}
		if ( 'alerts' === $section ) {
			$alertState = ( new AlertDelivery( $options, static fn(): bool => false, '', '' ) )->status();
			echo wp_kses( ( new AlertSettingsRenderer() )->render( '1' === $options->get( 'amsec_alerts_enabled' ), $alertState, admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_alert_settings' ), \AmazingPlugins\Security\Alerts\MailStatus::assess() ), AdminHtml::allowed() );
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-settings#amsec-notifications' ) ) . '">' . esc_html__( 'Open full notification settings', 'amazingplugins-security-scanner' ) . '</a></p>';
		}
	}

	private function vulnerabilitySection( bool $direct, WordPressVulnerabilityReportStore $vulnStore, mixed $vulnCurrent ): void {
		if ( $direct ) {
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_scan">';
			wp_nonce_field( 'amazing_security_vulnerability_scan' );
			submit_button( __( 'Check installed versions', 'amazingplugins-security-scanner' ) );
			echo '</form>';
			$scanProgress = get_transient( 'amsec_vuln_progress' );
			if ( is_array( $scanProgress ) ) {
				$phase = 'provenance' === ( $scanProgress['phase'] ?? null ) ? __( 'Verifying local release files', 'amazingplugins-security-scanner' ) : __( 'Checking published issues', 'amazingplugins-security-scanner' );
				echo '<p role="status">' . esc_html(
					sprintf(
						/* translators: 1: progress phase, 2: packages processed, 3: total packages. */
						__( '%1$s: %2$d of %3$d packages processed. The next batch is scheduled.', 'amazingplugins-security-scanner' ),
						$phase,
						(int) ( $scanProgress['offset'] ?? 0 ),
						(int) ( $scanProgress['total'] ?? 0 )
					)
				) . '</p>';
			}
			$kev = '1' === get_option( ExploitedList::ENABLED );
			echo '<section class="amsec-consent" aria-labelledby="amsec-kev-title"><h3 id="amsec-kev-title">' . esc_html__( 'Holes attackers are using right now', 'amazingplugins-security-scanner' ) . '</h3><p>' . esc_html__( 'Also check the US CISA list of security holes that attackers are using right now. Once a week this site downloads the public list. Nothing about your site is sent, but CISA can see your server’s IP address. A match is marked “Attackers are using this hole.”', 'amazingplugins-security-scanner' ) . ' <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">' . esc_html__( 'About the list', 'amazingplugins-security-scanner' ) . '</a> · <a href="https://www.cisa.gov/privacy-policy" target="_blank" rel="noopener noreferrer">' . esc_html__( 'CISA privacy policy', 'amazingplugins-security-scanner' ) . '</a></p>';
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_kev_toggle"><input type="hidden" name="amsec_kev" value="' . ( $kev ? '0' : '1' ) . '">';
			wp_nonce_field( 'amazing_security_kev_toggle' );
			echo '<p>';
			submit_button( $kev ? __( 'Turn off the CISA list', 'amazingplugins-security-scanner' ) : __( 'Turn on the CISA list', 'amazingplugins-security-scanner' ), $kev ? 'secondary' : 'primary', 'submit', false );
			echo '</p></form></section>';
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_disable">';
			wp_nonce_field( 'amazing_security_vulnerability_disable' );
			echo '<p>';
			submit_button( __( 'Turn off vulnerability checks', 'amazingplugins-security-scanner' ), 'secondary', 'submit', false );
			echo '</p>';
			echo '</form>';
		} else {
			echo '<section class="amsec-consent" aria-labelledby="amsec-consent-title"><h3 id="amsec-consent-title">' . esc_html__( 'Enable vulnerability checks', 'amazingplugins-security-scanner' ) . '</h3><p>' . esc_html__( 'This WordPress site will contact WPVulnerability directly for its core version and installed plugin and theme slugs. The provider can see this site’s request IP address and requested components. AmazingPlugins receives no inventory. Results are stored on this site. Read the', 'amazingplugins-security-scanner' ) . ' <a href="https://www.wpvulnerability.com/privacy/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'provider privacy policy', 'amazingplugins-security-scanner' ) . '</a> ' . esc_html__( 'and', 'amazingplugins-security-scanner' ) . ' <a href="https://www.wpvulnerability.com/license/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'data license', 'amazingplugins-security-scanner' ) . '</a>.</p>';
			echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_enable">';
			wp_nonce_field( 'amazing_security_vulnerability_enable' );
			echo '<p>';
			submit_button( __( 'Enable vulnerability checks', 'amazingplugins-security-scanner' ), 'primary', 'submit', false );
			echo '</p>';
			echo '</form></section>';
		}
		echo '<form action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post"><input type="hidden" name="action" value="amazing_security_vulnerability_clear">';
		wp_nonce_field( 'amazing_security_vulnerability_clear' );
		echo '<p>';
		submit_button( __( 'Clear local vulnerability data', 'amazingplugins-security-scanner' ), 'secondary', 'submit', false );
		echo '</p>';
		echo '</form>';
		// VulnerabilityReportRenderer escapes every dynamic value before constructing markup.
		echo wp_kses( ( new VulnerabilityReportRenderer() )->render( $vulnCurrent, $vulnStore->historical(), null, $direct ), AdminHtml::allowed() );
	}

	/**
	 * @param array<int, mixed> $results
	 */
	private function statusList( string $category, array $results, string $integrityScanId = '', string $contentScanId = '', string $fileScanId = '' ): void {
		$titles = array(
			'success'     => __( 'Success', 'amazingplugins-security-scanner' ),
			'error'       => __( 'Error', 'amazingplugins-security-scanner' ),
			'critical'    => __( 'Critical', 'amazingplugins-security-scanner' ),
			'warning'     => __( 'Warning', 'amazingplugins-security-scanner' ),
			'recommended' => __( 'Recommended', 'amazingplugins-security-scanner' ),
		);
		$notes  = array(
			'success'     => __( 'These are configured. Nothing to change here.', 'amazingplugins-security-scanner' ),
			'error'       => __( 'These need a change.', 'amazingplugins-security-scanner' ),
			'critical'    => __( 'These are serious gaps, such as missing two-factor or passkey coverage.', 'amazingplugins-security-scanner' ),
			'warning'     => __( 'These need a look.', 'amazingplugins-security-scanner' ),
			'recommended' => __( 'These are suggestions, or checks that could not be confirmed yet.', 'amazingplugins-security-scanner' ),
		);
		$rows   = array();
		foreach ( $results as $result ) {
			if ( $result instanceof CheckResult && self::statusOf( $result ) === $category ) {
				$rows[] = $result;
			}
		}
		$rows = $this->ranked( $rows );
		echo '<section class="amsec-overview" data-amsec-results aria-labelledby="amsec-start-title"><h2 id="amsec-start-title">' . esc_html( $titles[ $category ] ) . '</h2>';
		echo '<p>' . esc_html( $notes[ $category ] ) . '</p>';
		$per   = 6;
		$pages = max( 1, (int) ceil( count( $rows ) / $per ) );
		$paged = min( $this->requestedPage(), $pages );
		$slice = array_slice( $rows, ( $paged - 1 ) * $per, $per );
		if ( 1 === $paged && 'success' !== $category ) {
			$guideOptions = array( 'amsec_idle_minutes' => get_option( 'amsec_idle_minutes', '0' ) );
			foreach ( array_keys( Score::FLAGS ) as $guideKey ) {
				$guideOptions[ $guideKey ] = get_option( $guideKey, '0' );
			}
			$guideScore = Score::tally( $guideOptions );
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-guide' ) ) . '">' . esc_html(
				sprintf(
					/* translators: 1: number on, 2: number checked */
					__( 'Site review: %1$d of %2$d local protections are on.', 'amazingplugins-security-scanner' ),
					$guideScore['on'],
					$guideScore['total']
				)
			) . '</a></p>';
		}
		if ( array() === $slice ) {
			echo '<p>' . esc_html__( 'Nothing in this group.', 'amazingplugins-security-scanner' ) . '</p>';
		} else {
			$this->startItems( $slice, $integrityScanId, $contentScanId, $fileScanId, true, 'success' !== $category );
		}
		$this->pager( $category, $paged, $pages );
		$this->reportDownload();
		echo '</section>';
	}

	/**
	 * @param array<int, mixed> $results
	 */
	private function requestedCategory( array $results ): string {
		$raw = isset( $_GET['amsec_cat'] ) ? sanitize_key( wp_unslash( $_GET['amsec_cat'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Read-only view switch.
		// Recommended items live on the Recommendations page now.
		$allowed = array( 'success', 'error', 'critical', 'warning' );
		if ( in_array( $raw, $allowed, true ) ) {
			return $raw;
		}
		$counts = $this->scanCounts( $results );
		if ( $counts['fail'] > 0 ) {
			return 'error';
		}
		if ( $counts['critical'] > 0 ) {
			return 'critical';
		}
		if ( $counts['warn'] > 0 ) {
			return 'warning';
		}
		return 'success';
	}

	private function requestedPage(): int {
		$raw = isset( $_GET['amsec_paged'] ) ? absint( wp_unslash( $_GET['amsec_paged'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Read-only page number.
		return max( 1, $raw );
	}

	private function viewUrl( string $category, int $paged = 1 ): string {
		$args = array(
			'page'      => 'amazing-security',
			'amsec_cat' => $category,
		);
		if ( $paged > 1 ) {
			$args['amsec_paged'] = $paged;
		}
		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array{success: int, fail: int, critical: int, warn: int, recommended: int} $counts
	 */
	private function categoryNav( string $current, array $counts ): void {
		$items = array(
			'success'  => array( __( 'Success', 'amazingplugins-security-scanner' ), $counts['success'] ),
			'error'    => array( __( 'Error', 'amazingplugins-security-scanner' ), $counts['fail'] ),
			'critical' => array( __( 'Critical', 'amazingplugins-security-scanner' ), $counts['critical'] ),
			'warning'  => array( __( 'Warning', 'amazingplugins-security-scanner' ), $counts['warn'] ),
		);
		echo '<nav class="amsec-cats" aria-label="' . esc_attr__( 'Report categories', 'amazingplugins-security-scanner' ) . '">';
		foreach ( $items as $slug => $item ) {
			echo '<a class="is-' . esc_attr( $slug ) . ( $slug === $current ? ' is-current' : '' ) . '"' . ( $slug === $current ? ' aria-current="page"' : '' ) . ' href="' . esc_url( $this->viewUrl( $slug ) ) . '">' . esc_html( $item[0] ) . ' <span class="amsec-cat-count">' . esc_html( (string) $item[1] ) . '</span></a>';
		}
		echo '</nav>';
	}

	private function pager( string $category, int $paged, int $pages ): void {
		if ( $pages < 2 ) {
			return;
		}
		echo '<nav class="amsec-pager" aria-label="' . esc_attr__( 'Results pages', 'amazingplugins-security-scanner' ) . '">';
		if ( $paged > 1 ) {
			echo '<a class="amsec-pager-nav" href="' . esc_url( $this->viewUrl( $category, $paged - 1 ) ) . '">' . esc_html__( 'Previous', 'amazingplugins-security-scanner' ) . '</a>';
		} else {
			echo '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Previous', 'amazingplugins-security-scanner' ) . '</span>';
		}
		echo '<span class="amsec-pager-label">' . esc_html(
			sprintf(
				/* translators: 1: current page, 2: page count. */
				__( 'Page %1$d of %2$d', 'amazingplugins-security-scanner' ),
				$paged,
				$pages
			)
		) . '</span>';
		if ( $paged < $pages ) {
			echo '<a class="amsec-pager-nav" href="' . esc_url( $this->viewUrl( $category, $paged + 1 ) ) . '">' . esc_html__( 'Next', 'amazingplugins-security-scanner' ) . '</a>';
		} else {
			echo '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Next', 'amazingplugins-security-scanner' ) . '</span>';
		}
		echo '</nav>';
	}

	private function categoryForHash( string $hash ): string {
		return match ( $hash ) {
			'amsec-hardening' => 'hardening',
			'amsec-integrity', 'amsec-file-scan' => 'files',
			'amsec-vulnerabilities' => 'vulnerabilities',
			default => 'more',
		};
	}

	/**
	 * @param array<int, mixed> $results
	 */
	private function startItems( array $results, string $integrityScanId, string $contentScanId, string $fileScanId, bool $wrap = true, bool $actions = true ): void {
		if ( $wrap ) {
			echo '<ul class="amsec-start">';
		}
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
				'none' => __( 'Not run', 'amazingplugins-security-scanner' ),
				'partial' => __( 'Continue', 'amazingplugins-security-scanner' ),
				'critical' => __( 'Critical', 'amazingplugins-security-scanner' ),
				'warn', 'fail' => __( 'Review', 'amazingplugins-security-scanner' ),
				'pass' => __( 'Success', 'amazingplugins-security-scanner' ),
				default => __( 'Recommended', 'amazingplugins-security-scanner' ),
			};
			echo '<li class="amsec-start-item' . ( $actions ? '' : ' is-quiet' ) . '" data-state="' . esc_attr( $tone ) . '"><span class="amsec-start-badge">' . esc_html( $badge ) . '</span><span class="amsec-start-copy"><strong>' . esc_html( StartHere::label( $result->checkId ) ) . '</strong> ' . esc_html( $result->summary ) . '</span>';
			if ( $actions ) {
				$this->startControl( StartHere::control( $result ), $integrityScanId, $contentScanId, $fileScanId );
			}
			echo '</li>';
		}
		if ( $wrap ) {
			echo '</ul>';
		}
	}

	private function reportDownload(): void {
		echo '<form class="amsec-start-action" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_findings_report">';
		wp_nonce_field( 'amsec_findings_report' );
		echo '<button type="submit" class="button">' . esc_html__( 'Download findings', 'amazingplugins-security-scanner' ) . '</button></form>';
		echo '<p>' . esc_html__( 'The file is a starting list for a host. It is not a compliance report, and it does not start a new check.', 'amazingplugins-security-scanner' ) . '</p>';
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
		if ( isset( $control['install'] ) ) {
			echo ' <a class="button" href="' . esc_url( RequiredTotpPage::directoryUrl( $control['install'] ) ) . '">' . esc_html( $control['label'] ) . '</a>';
			return;
		}
		if ( isset( $control['page'] ) ) {
			$target = admin_url( 'admin.php?page=' . $control['page'] );
			if ( isset( $control['hash'] ) && 1 === preg_match( '/^[a-z0-9-]+$/', $control['hash'] ) ) {
				$target .= '#' . $control['hash'];
			}
			echo ' <a class="button" href="' . esc_url( $target ) . '">' . esc_html( $control['label'] ) . '</a>';
			return;
		}
		if ( isset( $control['hash'] ) ) {
			echo ' <a class="button" href="' . esc_url( $this->viewUrl( $this->categoryForHash( $control['hash'] ) ) . '#' . $control['hash'] ) . '">' . esc_html( $control['label'] ) . '</a>';
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
					'label'  => __( 'Run integrity scan', 'amazingplugins-security-scanner' ),
					'action' => 'amazing_security_integrity_start',
					'nonce'  => 'amazing_security_integrity_start',
				),
				'files' => array(
					'label'  => __( 'Run file scan', 'amazingplugins-security-scanner' ),
					'action' => 'amazing_security_file_scan_start',
					'nonce'  => 'amazing_security_file_scan_start',
				),
				default => array(
					'label' => __( 'Review content scan', 'amazingplugins-security-scanner' ),
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
}
