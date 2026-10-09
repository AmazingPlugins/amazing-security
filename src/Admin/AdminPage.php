<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Alerts\AlertDelivery;
use AmazingPlugins\Security\Alerts\AlertSettingsRenderer;
use AmazingPlugins\Security\Content\WordPressContentService;
use AmazingPlugins\Security\FileScan\WordPressFileScanStore;
use AmazingPlugins\Security\Findings\CheckResult;
use AmazingPlugins\Security\Findings\FindingsRepository;
use AmazingPlugins\Security\Integrity\WordPressIntegrityStore;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Free\Guide\Score;
use AmazingPlugins\Security\Schedule\LocalSchedule;
use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use AmazingPlugins\Security\Schedule\SuiteCycle;
use AmazingPlugins\Security\Vulnerabilities\VulnerabilityPreferences;
use AmazingPlugins\Security\Vulnerabilities\WordPressVulnerabilityReportStore;

final class AdminPage {
	public function register(): void {
		add_menu_page( __( 'Amazing Security', 'amazing-security' ), __( 'Amazing Security', 'amazing-security' ), 'manage_options', 'amazing-security', array( $this, 'render' ), 'dashicons-shield-alt', 81 );
		add_action( 'admin_menu', array( new FilesPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new FollowUpPages(), 'register' ), 20 );
		add_action( 'admin_menu', array( new RecordsPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new ToolIndex(), 'register' ), 20 );
		add_action( 'admin_menu', array( StartPanel::class, 'register' ), 20 );
		add_action( 'admin_menu', array( new ReviewPage(), 'register' ), 20 );
		add_action( 'admin_menu', array( new UploadsRulePage(), 'register' ), 20 );
		add_action( 'admin_post_amsec_uploads_rule', array( new UploadsRulePage(), 'save' ) );
		add_action( 'admin_menu', array( Submenu::class, 'trim' ), 999 );
		Brand::boot();
	}

	private function renderFirstScan(): void {
		echo '<div class="wrap amazing-security-admin amsec-scan amsec-scan-first"><div class="amsec-stage">';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice after a failed scan redirect.
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error" data-amsec-scan-error><p>' . esc_html__( 'Scan could not be saved.', 'amazing-security' ) . '</p></div>';
		}
		echo '<p class="amsec-scan-empty">' . esc_html__( 'No scan has been saved yet.', 'amazing-security' ) . '</p>';
		$this->scanForm( false, __( 'Scan', 'amazing-security' ) );
		echo '</div></div>';
	}

	/**
	 * @param array<int, mixed>|null $results
	 */
	private function scanForm( bool $withConsent, string $label, ?array $results = null ): void {
		$rescan = null !== $results;
		echo '<form class="amsec-scan-form' . ( $rescan ? ' amsec-rescan-bar' : '' ) . '" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" method="post">';
		echo '<input type="hidden" name="action" value="amazing_security_scan">';
		wp_nonce_field( 'amazing_security_scan' );
		if ( $rescan ) {
			echo '<div class="amsec-rescan-row">';
			$counts = $this->scanCounts( $results );
			echo '<ul class="amsec-scan-summary">';
			echo '<li class="is-success"><a href="' . esc_url( $this->viewUrl( 'success' ) ) . '"><strong>' . esc_html( (string) $counts['success'] ) . '</strong> ' . esc_html__( 'Success', 'amazing-security' ) . '</a></li>';
			echo '<li class="is-error"><a href="' . esc_url( $this->viewUrl( 'error' ) ) . '"><strong>' . esc_html( (string) $counts['fail'] ) . '</strong> ' . esc_html__( 'Errors', 'amazing-security' ) . '</a></li>';
			echo '<li class="is-critical"><a href="' . esc_url( $this->viewUrl( 'critical' ) ) . '"><strong>' . esc_html( (string) $counts['critical'] ) . '</strong> ' . esc_html__( 'Critical', 'amazing-security' ) . '</a></li>';
			echo '<li class="is-warn"><a href="' . esc_url( $this->viewUrl( 'warning' ) ) . '"><strong>' . esc_html( (string) $counts['warn'] ) . '</strong> ' . esc_html__( 'Warnings', 'amazing-security' ) . '</a></li>';
			echo '<li class="is-recommended"><a href="' . esc_url( $this->viewUrl( 'recommended' ) ) . '"><strong>' . esc_html( (string) $counts['recommended'] ) . '</strong> ' . esc_html__( 'Recommended', 'amazing-security' ) . '</a></li>';
			echo '</ul>';
		}
		echo '<button type="submit" class="amsec-scan-button' . ( $rescan ? ' amsec-rescan-button' : '' ) . '">' . esc_html( $label ) . '</button>';
		if ( $rescan ) {
			echo '<div class="amsec-scan-progress" hidden><p class="amsec-scan-status" role="status">' . esc_html__( 'Scanning', 'amazing-security' ) . '</p>';
			echo '<div class="amsec-scan-track" aria-hidden="true"><span class="amsec-scan-fill"></span></div></div></div>';
		}
		if ( $withConsent ) {
			echo '<label class="amsec-header-consent"><input type="checkbox" name="amsec_header_consent" value="1"> ' . esc_html__( "Request this site's homepage and read its response headers.", 'amazing-security' ) . '</label>';
		}
		if ( ! $rescan ) {
			echo '<div class="amsec-scan-progress" hidden><p class="amsec-scan-status" role="status">' . esc_html__( 'Scanning', 'amazing-security' ) . '</p>';
			echo '<div class="amsec-scan-track" aria-hidden="true"><span class="amsec-scan-fill"></span></div></div>';
		}
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
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$run = ( new FindingsRepository() )->latest();
		if ( null === $run ) {
			$this->renderFirstScan();
			return;
		}
		$options      = new WordPressOptions();
		$progress     = ( new WordPressIntegrityStore( $options ) )->latestProgress();
		$fileProgress = ( new WordPressFileScanStore( $options ) )->latestProgress();
		echo '<div class="wrap amazing-security-admin amsec-scan">';
		$this->scanForm( true, __( 'Rescan', 'amazing-security' ), $run->results );
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
		// These flags select a static message only.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['amazing_security_error'] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Scan could not be saved. The previous report is still shown.', 'amazing-security' ) . '</p></div>';
		}
		$category = $this->requestedCategory( $run->results );
		$this->categoryNav( $category );
		$this->statusList( $category, $run->results, $integrityScanId, $contentScanId, $fileScanId );
		echo '</div>';
	}

	public function renderSection( string $section ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
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
			echo ( new FileScanReportRenderer( admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_file_scan_note' ), $fileStore->notes() ) )->render( $fileDone, $fileProgress, $fileHistory );
			return;
		}
		if ( 'vulnerabilities' === $section ) {
			$this->vulnerabilitySection( $direct, $vulnStore, $vulnCurrent );
			return;
		}
		if ( 'schedule' === $section ) {
			// ScheduleStatusRenderer escapes dynamic values.
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo ( new ScheduleStatusRenderer() )->render( ( new LocalSchedule( $options ) )->status( time() ) );
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo ( new ScheduleStatusRenderer() )->renderSuite( ( new SuiteCycle( $options ) )->status( time() ) );
			return;
		}
		if ( 'alerts' === $section ) {
			$alertState = ( new AlertDelivery( $options, static fn(): bool => false, '', '' ) )->status();
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo ( new AlertSettingsRenderer() )->render( '1' === $options->get( 'amsec_alerts_enabled' ), $alertState, admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_alert_settings' ), \AmazingPlugins\Security\Alerts\MailStatus::assess() );
			echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=amsec-settings#amsec-notifications' ) ) . '">' . esc_html__( 'Open full notification settings', 'amazing-security' ) . '</a></p>';
		}
	}

	private function vulnerabilitySection( bool $direct, WordPressVulnerabilityReportStore $vulnStore, mixed $vulnCurrent ): void {
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
	}

	/**
	 * @param array<int, mixed> $results
	 */
	private function statusList( string $category, array $results, string $integrityScanId = '', string $contentScanId = '', string $fileScanId = '' ): void {
		$titles = array(
			'success'     => __( 'Success', 'amazing-security' ),
			'error'       => __( 'Error', 'amazing-security' ),
			'critical'    => __( 'Critical', 'amazing-security' ),
			'warning'     => __( 'Warning', 'amazing-security' ),
			'recommended' => __( 'Recommended', 'amazing-security' ),
		);
		$notes  = array(
			'success'     => __( 'These are configured. Nothing to change here.', 'amazing-security' ),
			'error'       => __( 'These need a change.', 'amazing-security' ),
			'critical'    => __( 'These are serious gaps, such as missing two-factor or passkey coverage.', 'amazing-security' ),
			'warning'     => __( 'These need a look.', 'amazing-security' ),
			'recommended' => __( 'These are suggestions, or checks that could not be confirmed yet.', 'amazing-security' ),
		);
		$ranked = array_flip( array_merge( StartHere::ORDER, StartHere::LATER ) );
		$rows   = array();
		foreach ( $results as $result ) {
			if ( $result instanceof CheckResult && self::statusOf( $result ) === $category ) {
				$rows[] = $result;
			}
		}
		usort(
			$rows,
			static function ( CheckResult $left, CheckResult $right ) use ( $ranked ): int {
				$leftRank  = $ranked[ $left->checkId ] ?? 1000;
				$rightRank = $ranked[ $right->checkId ] ?? 1000;
				return $leftRank <=> $rightRank;
			}
		);
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
					__( 'Site review: %1$d of %2$d local protections are on.', 'amazing-security' ),
					$guideScore['on'],
					$guideScore['total']
				)
			) . '</a></p>';
		}
		if ( array() === $slice ) {
			echo '<p>' . esc_html__( 'Nothing in this group.', 'amazing-security' ) . '</p>';
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
		if ( 'info' === $raw ) {
			$raw = 'recommended';
		}
		$allowed = array( 'success', 'error', 'critical', 'warning', 'recommended' );
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
		if ( $counts['recommended'] > 0 ) {
			return 'recommended';
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

	private function categoryNav( string $current ): void {
		$items = array(
			'success'     => __( 'Success', 'amazing-security' ),
			'error'       => __( 'Error', 'amazing-security' ),
			'critical'    => __( 'Critical', 'amazing-security' ),
			'warning'     => __( 'Warning', 'amazing-security' ),
			'recommended' => __( 'Recommended', 'amazing-security' ),
		);
		echo '<nav class="amsec-cats" aria-label="' . esc_attr__( 'Report categories', 'amazing-security' ) . '">';
		foreach ( $items as $slug => $label ) {
			echo '<a' . ( $slug === $current ? ' class="is-current" aria-current="page"' : '' ) . ' href="' . esc_url( $this->viewUrl( $slug ) ) . '">' . esc_html( $label ) . '</a>';
		}
		echo '</nav>';
	}

	private function pager( string $category, int $paged, int $pages ): void {
		if ( $pages < 2 ) {
			return;
		}
		echo '<nav class="amsec-pager" aria-label="' . esc_attr__( 'Results pages', 'amazing-security' ) . '">';
		if ( $paged > 1 ) {
			echo '<a class="amsec-pager-nav" href="' . esc_url( $this->viewUrl( $category, $paged - 1 ) ) . '">' . esc_html__( 'Previous', 'amazing-security' ) . '</a>';
		} else {
			echo '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Previous', 'amazing-security' ) . '</span>';
		}
		echo '<span class="amsec-pager-label">' . esc_html(
			sprintf(
				/* translators: 1: current page, 2: page count. */
				__( 'Page %1$d of %2$d', 'amazing-security' ),
				$paged,
				$pages
			)
		) . '</span>';
		if ( $paged < $pages ) {
			echo '<a class="amsec-pager-nav" href="' . esc_url( $this->viewUrl( $category, $paged + 1 ) ) . '">' . esc_html__( 'Next', 'amazing-security' ) . '</a>';
		} else {
			echo '<span class="amsec-pager-nav is-spacer" aria-hidden="true">' . esc_html__( 'Next', 'amazing-security' ) . '</span>';
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
				'none' => 'Not run',
				'partial' => 'Continue',
				'critical' => 'Critical',
				'warn', 'fail' => 'Review',
				'pass' => 'Success',
				default => 'Recommended',
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
}
