<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Integrity, file scan, vulnerability checks, and the daily cycle. Hidden from the side menu. */
final class FollowUpPages {
	public function register(): void {
		add_submenu_page( 'ironlatch-security-scanner', __( 'Integrity and file scan', 'ironlatch-security-scanner' ), __( 'Integrity and file scan', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-file-checks', array( $this, 'files' ) );
		add_submenu_page( 'ironlatch-security-scanner', __( 'Published vulnerabilities', 'ironlatch-security-scanner' ), __( 'Published vulnerabilities', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-vulnerabilities', array( $this, 'vulnerabilities' ) );
		add_submenu_page( 'ironlatch-security-scanner', __( 'Daily checks', 'ironlatch-security-scanner' ), __( 'Daily checks', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-schedule', array( $this, 'schedule' ) );
	}

	public function files(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Integrity and file scan', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'Compare installed release files, then review unfamiliar PHP. Each scan starts from its own button.', 'ironlatch-security-scanner' ) . '</p>';
		$this->notice( 'ironlatch_security_scanner_integrity_error', __( 'Integrity scan could not finish. The previous completed report remains available.', 'ironlatch-security-scanner' ) );
		$this->notice( 'ironlatch_security_scanner_file_scan_error', __( 'File scan could not finish. The previous completed report remains available.', 'ironlatch-security-scanner' ) );
		( new AdminPage() )->renderSection( 'files' );
		echo '</div>';
	}

	public function vulnerabilities(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap ironlatch-security-scanner-admin" id="ironlatch-vulnerabilities-page"><h1>' . esc_html__( 'Published vulnerabilities', 'ironlatch-security-scanner' ) . '</h1>';
		$this->notice( 'ironlatch_security_scanner_vulnerability_error', __( 'Vulnerability inventory could not be saved. The previous report remains available.', 'ironlatch-security-scanner' ) );
		( new AdminPage() )->renderSection( 'vulnerabilities' );
		echo '</div>';
	}

	public function schedule(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap ironlatch-security-scanner-admin"><h1>' . esc_html__( 'Daily checks', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p>' . esc_html__( 'This page shows whether the local cycle is waiting. It does not start a check.', 'ironlatch-security-scanner' ) . '</p>';
		( new AdminPage() )->renderSection( 'schedule' );
		echo '</div>';
	}

	private function notice( string $flag, string $message ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only notice after a failed redirect.
		if ( isset( $_GET[ $flag ] ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $message ) . '</p></div>';
		}
	}
}
