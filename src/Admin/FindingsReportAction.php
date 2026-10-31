<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Findings\FindingsReport;
use AmazingPlugins\Security\Findings\FindingsRepository;

/** Sends the stored local findings as a text file. It does not start a scan. */
final class FindingsReportAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) || ! FixApprovalAction::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_findings_report' );
		$report = FindingsReport::text( ( new FindingsRepository() )->latest() );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="amsec-security-scanner-findings.txt"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $report; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Plain-text download, not HTML.
		exit;
	}
}
