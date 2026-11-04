<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Fixes\ApprovedSetting;
use AmazingPlugins\Security\Scan\LocalHardeningScanService;
use Throwable;

/** Applies one already-reviewed setting. It does not edit wp-config.php. */
final class ApprovedSettingAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) || ! FixApprovalAction::cookieAuthenticated() ) {
			wp_die( esc_html__( 'A current administrator session is required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_approved_setting' );
		// The nonce is verified above before the operation is applied.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$operation = isset( $_POST['operation'] ) && is_string( $_POST['operation'] ) ? sanitize_key( wp_unslash( $_POST['operation'] ) ) : '';
		$changed   = match ( $operation ) {
			'close-pingbacks' => $this->closePingbacks(),
			'disable-file-editor' => $this->disableFileEditor(),
			'restore-file-editor' => $this->restoreFileEditor(),
			'enable-login-confirm' => $this->writeGate( 'ironlatch_login_confirm', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_login_confirm' ) ) ),
			'disable-login-confirm' => $this->writeGate( 'ironlatch_login_confirm', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_login_confirm' ) ) ),
			'enable-common-passwords' => $this->writeGate( 'ironlatch_common_passwords', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_common_passwords' ) ) ),
			'disable-common-passwords' => $this->writeGate( 'ironlatch_common_passwords', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_common_passwords' ) ) ),
			'enable-login-hints' => $this->writeGate( 'ironlatch_generic_login_errors', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_generic_login_errors' ) ) ),
			'disable-login-hints' => $this->writeGate( 'ironlatch_generic_login_errors', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_generic_login_errors' ) ) ),
			'enable-author-archives' => $this->writeGate( 'ironlatch_hide_author_archives', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_hide_author_archives' ) ) ),
			'disable-author-archives' => $this->writeGate( 'ironlatch_hide_author_archives', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_hide_author_archives' ) ) ),
			'enable-rest-users' => $this->writeGate( 'ironlatch_hide_rest_users', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_hide_rest_users' ) ) ),
			'disable-rest-users' => $this->writeGate( 'ironlatch_hide_rest_users', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_hide_rest_users' ) ) ),
			'enable-version-tag' => $this->writeGate( 'ironlatch_hide_generator', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_hide_generator' ) ) ),
			'disable-version-tag' => $this->writeGate( 'ironlatch_hide_generator', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_hide_generator' ) ) ),
			'enable-discovery-links' => $this->writeGate( 'ironlatch_hide_discovery_links', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_hide_discovery_links' ) ) ),
			'disable-discovery-links' => $this->writeGate( 'ironlatch_hide_discovery_links', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_hide_discovery_links' ) ) ),
			'disable-application-passwords' => $this->writeGate( 'ironlatch_disable_application_passwords', ApprovedSetting::gateOn( $this->gateValue( 'ironlatch_disable_application_passwords' ) ) ),
			'enable-application-passwords' => $this->writeGate( 'ironlatch_disable_application_passwords', ApprovedSetting::gateOff( $this->gateValue( 'ironlatch_disable_application_passwords' ) ) ),
			default => false,
		};
		if ( ! $changed ) {
			wp_die( esc_html__( 'That setting was not changed.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		try {
			( new LocalHardeningScanService() )->run();
		} catch ( Throwable ) {
			wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-security-scanner#ironlatch-start-title' ) );
			exit;
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-security-scanner#ironlatch-start-title' ) );
		exit;
	}

	private function closePingbacks(): bool {
		$status = get_option( 'default_ping_status', '' );
		if ( 'closed' !== ApprovedSetting::pingStatus( is_string( $status ) ? $status : '' ) ) {
			return false;
		}
		return true === update_option( 'default_ping_status', 'closed' );
	}

	private function disableFileEditor(): bool {
		if ( '' === ApprovedSetting::fileEditorOption( defined( 'DISALLOW_FILE_EDIT' ) ) ) {
			return false;
		}
		if ( true !== update_option( 'ironlatch_disallow_file_edit', '1' ) && '1' !== get_option( 'ironlatch_disallow_file_edit', '0' ) ) {
			return false;
		}
		return true;
	}

	private function restoreFileEditor(): bool {
		$current = get_option( 'ironlatch_disallow_file_edit', '0' );
		$next    = ApprovedSetting::fileEditorRestore( is_string( $current ) ? $current : '' );
		return '' !== $next && true === update_option( 'ironlatch_disallow_file_edit', $next );
	}

	private function gateValue( string $option ): string {
		$current = get_option( $option, '0' );
		return is_string( $current ) ? $current : '0';
	}

	private function writeGate( string $option, string $next ): bool {
		if ( '' === $next ) {
			return false;
		}
		if ( true === update_option( $option, $next ) ) {
			return true;
		}
		$stored = get_option( $option, '0' );
		return ( is_string( $stored ) ? $stored : '' ) === $next;
	}
}
