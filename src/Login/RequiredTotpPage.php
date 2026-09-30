<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

final class RequiredTotpPage {
	public function register(): void {
		add_submenu_page( 'amazing-security', 'Required verification', 'Required verification', 'manage_options', 'amsec-required-totp', array( $this, 'render' ) );
	}

	public function notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		try {
			$status = ( new RequiredTotpPolicy() )->status( get_current_user_id() );
		} catch ( \Throwable ) {
			$status = 'unavailable';
		}
		if ( in_array( $status, array( 'new', 'grace', 'expired', 'unavailable' ), true ) ) {
			echo '<div class="notice notice-warning"><p>Administrator verification policy: ' . esc_html( $status ) . '. Enroll your authenticator in <a href="' . esc_url( admin_url( 'admin.php?page=amazing-security#amsec-login-title' ) ) . '">Amazing Security</a>. Review recovery before your next login.</p></div>';
		}
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap"><h1>Required administrator verification</h1><p>Unenrolled administrators get seven days from their first native password login to set up verification. After that, native interactive password login is refused. Existing sessions remain active. REST/application passwords, XML-RPC, WP-CLI and custom SSO are outside this policy.</p><p>Enroll your own authenticator and save recovery codes before enabling. An enrolled administrator can grant another account a new seven-day grace period. Host recovery: <code>wp amazing-security policy disable</code>. This leaves voluntary factors active; use the existing per-account recovery command if needed.</p>';
		try {
			$enabled = null !== ( new RequiredTotpPolicy() )->generation();
		} catch ( \Throwable ) {
			echo '<p>Policy unavailable. Use host-level recovery.</p></div>';
			return;
		}
		echo '<p>Policy: <strong>' . ( $enabled ? 'On' : 'Off' ) . '</strong></p>';
		if ( ! is_ssl() || ! ( new WordPressTotpStore( $GLOBALS['wpdb'] ) )->isEnrolled( get_current_user_id() ) ) {
			echo '<p>HTTPS and an enrolled approving administrator are required to change this policy.</p></div>';
			return;
		}
		$this->form( $enabled ? 'disable' : 'enable', get_current_user_id() );
		if ( $enabled ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only selection; approval checks target.
			$id = isset( $_GET['user_id'] ) && is_scalar( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
			echo '<h2>Grant enrollment grace</h2><form method="get"><input type="hidden" name="page" value="amsec-required-totp"><label>Other administrator user ID <input type="number" name="user_id" min="1" required></label> <button class="button">Select account</button></form>';
			if ( $id > 0 && get_current_user_id() !== $id && current_user_can( 'edit_user', $id ) && user_can( $id, 'manage_options' ) ) {
				$this->form( 'grace', $id );
			}
		}
		echo '</div>';
	}

	private function form( string $mode, int $id ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_totp_policy"><input type="hidden" name="mode" value="' . esc_attr( $mode ) . '"><input type="hidden" name="user_id" value="' . esc_attr( (string) $id ) . '"><p>Action: ' . esc_html( $mode ) . '; selected account ID: ' . esc_html( (string) $id ) . '</p>';
		wp_nonce_field( 'amsec_totp_policy_' . $mode . '_' . $id );
		echo '<p><label>Your password <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label>Current code or recovery code <input type="text" name="factor" autocomplete="one-time-code" maxlength="64" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> I understand the login and recovery impact.</label></p>';
		submit_button( 'Approve ' . $mode, 'secondary' );
		echo '</form>';
	}
}
