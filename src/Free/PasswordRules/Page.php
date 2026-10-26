<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\PasswordRules;

defined( 'ABSPATH' ) || exit;

/** Password rule screen. Posts to admin-post.php. */
final class Page {
	public function register(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Password rules', 'amazing-security-scanner' ),
			__( 'Password rules', 'amazing-security-scanner' ),
			'manage_options',
			'amsec-password-rules',
			array( $this, 'render' )
		);
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$current = Module::stored();
		$notice  = $this->notice();
		echo '<div class="wrap amazing-security-admin">';
		echo '<h1>' . esc_html__( 'Password rules', 'amazing-security-scanner' ) . '</h1>';
		if ( '' !== $notice ) {
			echo '<div class="notice notice-info"><p>' . esc_html( $notice ) . '</p></div>';
		}
		echo '<p>' . esc_html__( 'These rules apply to a new password or a reset password. Off does nothing. Signing in is not checked.', 'amazing-security-scanner' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_password_rules">';
		wp_nonce_field( 'amsec_password_rules_save' );
		echo '<p><label for="' . esc_attr( Decision::OPTION ) . '">' . esc_html__( 'Minimum length', 'amazing-security-scanner' ) . ' ';
		echo '<select name="' . esc_attr( Decision::OPTION ) . '" id="' . esc_attr( Decision::OPTION ) . '">';
		foreach ( $this->choices() as $value => $label ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></label></p>';
		foreach ( $this->flags() as $option => $label ) {
			echo '<p><label><input type="checkbox" name="' . esc_attr( $option ) . '" value="1"' . checked( '1', $this->flag( $option ), false ) . '> ' . esc_html( $label ) . '</label></p>';
		}
		submit_button( __( 'Update password rules', 'amazing-security-scanner' ) );
		echo '</form></div>';
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_password_rules_save' );
		$posted = '0';
		if ( isset( $_POST[ Decision::OPTION ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- check_admin_referer already ran for this save.
			$posted = sanitize_text_field( wp_unslash( (string) $_POST[ Decision::OPTION ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- check_admin_referer already ran for this save.
		}
		update_option( Decision::OPTION, Decision::normalize( $posted ) );
		foreach ( array_keys( $this->flags() ) as $option ) {
			update_option( $option, $this->postedFlag( $option ), false );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-accounts&amsec_password_rules=updated#password-rules' ) );
		exit;
	}

	/**
	 * @return array<string, string>
	 */
	private function choices(): array {
		return array(
			'0'  => __( 'Off', 'amazing-security-scanner' ),
			'8'  => __( '8 characters', 'amazing-security-scanner' ),
			'12' => __( '12 characters', 'amazing-security-scanner' ),
			'16' => __( '16 characters', 'amazing-security-scanner' ),
		);
	}

	/**
	 * @return array<string, string>
	 */
	private function flags(): array {
		return array(
			Decision::NUMBER => __( 'Require a number', 'amazing-security-scanner' ),
			Decision::MIXED  => __( 'Require an uppercase letter and a lowercase letter', 'amazing-security-scanner' ),
			Decision::SYMBOL => __( 'Require a symbol', 'amazing-security-scanner' ),
			Decision::NAME   => __( 'Reject a password that includes the account name or email name', 'amazing-security-scanner' ),
			Decision::REUSE  => __( 'Reject the current password when it is changed', 'amazing-security-scanner' ),
		);
	}

	private function flag( string $option ): string {
		$value = get_option( $option, '0' );
		return Decision::enabled( is_scalar( $value ) ? (string) $value : '0' ) ? '1' : '0';
	}

	private function postedFlag( string $option ): string {
		if ( ! isset( $_POST[ $option ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- check_admin_referer already ran for this save.
			return '0';
		}
		$raw = sanitize_text_field( wp_unslash( (string) $_POST[ $option ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- check_admin_referer already ran for this save.
		return '1' === $raw ? '1' : '0';
	}

	private function notice(): string {
		$status = isset( $_GET['amsec_password_rules'] ) ? sanitize_key( wp_unslash( (string) $_GET['amsec_password_rules'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only status flag after a verified update redirect.
		if ( 'updated' === $status ) {
			return __( 'Password rules updated.', 'amazing-security-scanner' );
		}
		return '';
	}
}
