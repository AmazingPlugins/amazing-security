<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

/** Integrity, file scan, vulnerability checks, and the daily cycle. Hidden from the side menu. */
final class FollowUpPages {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Integrity and file scan', 'amazing-security' ), __( 'Integrity and file scan', 'amazing-security' ), 'manage_options', 'amsec-file-checks', array( $this, 'files' ) );
		add_submenu_page( 'amazing-security', __( 'Published vulnerabilities', 'amazing-security' ), __( 'Published vulnerabilities', 'amazing-security' ), 'manage_options', 'amsec-vulnerabilities', array( $this, 'vulnerabilities' ) );
		add_submenu_page( 'amazing-security', __( 'Daily checks', 'amazing-security' ), __( 'Daily checks', 'amazing-security' ), 'manage_options', 'amsec-schedule', array( $this, 'schedule' ) );
	}

	public function files(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Integrity and file scan', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'Compare installed release files, then review unfamiliar PHP. Each scan starts from its own button.', 'amazing-security' ) . '</p>';
		$this->notice( 'amazing_security_integrity_error', __( 'Integrity scan could not finish. The previous completed report remains available.', 'amazing-security' ) );
		$this->notice( 'amazing_security_file_scan_error', __( 'File scan could not finish. The previous completed report remains available.', 'amazing-security' ) );
		( new AdminPage() )->renderSection( 'files' );
		echo '</div>';
	}

	public function vulnerabilities(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin" id="amsec-vulnerabilities-page"><h1>' . esc_html__( 'Published vulnerabilities', 'amazing-security' ) . '</h1>';
		$this->notice( 'amazing_security_vulnerability_error', __( 'Vulnerability inventory could not be saved. The previous report remains available.', 'amazing-security' ) );
		( new AdminPage() )->renderSection( 'vulnerabilities' );
		echo '</div>';
	}

	public function schedule(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to view this report.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap amazing-security-admin"><h1>' . esc_html__( 'Daily checks', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'This page shows whether the local cycle is waiting. It does not start a check.', 'amazing-security' ) . '</p>';
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
