<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\LoginNotice;

/** Sign-in email screen. The option stays off until an administrator saves it. */
final class Page {
	public static function menu(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Sign-in email', 'amazing-security' ),
			__( 'Sign-in email', 'amazing-security' ),
			'manage_options',
			'amsec-login-notice',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$flag = Decision::flag( self::stored() );
		echo '<div class="wrap amazing-security-admin">';
		echo '<h1>' . esc_html__( 'Sign-in email', 'amazing-security' ) . '</h1>';
		echo '<p>' . esc_html__( 'This stays off until you turn it on.', 'amazing-security' ) . '</p>';
		echo '<p>' . esc_html( self::status( $flag ) ) . '</p>';
		echo '<p>' . esc_html__( 'When it is on, an administrator sign-in can send one email to that account. The next email waits one hour. The message is the site name and the UTC time. If the email cannot be sent, the sign-in still finishes.', 'amazing-security' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_login_notice_save">';
		wp_nonce_field( 'amsec_login_notice_save' );
		echo '<p><label for="amsec-login-email">' . esc_html__( 'Sign-in email', 'amazing-security' ) . ' ';
		echo '<select name="' . esc_attr( Decision::OPTION ) . '" id="amsec-login-email">';
		echo '<option value="0"' . selected( '1' === $flag ? '1' : '0', '0', false ) . '>' . esc_html__( 'Off', 'amazing-security' ) . '</option>';
		echo '<option value="1"' . selected( '1' === $flag ? '1' : '0', '1', false ) . '>' . esc_html__( 'On', 'amazing-security' ) . '</option>';
		echo '</select></label></p>';
		submit_button( __( 'Save sign-in email', 'amazing-security' ) );
		echo '</form>';
		echo '</div>';
	}

	public static function save(): void {
		if ( ! self::postRequest() ) {
			wp_die( esc_html__( 'Open the sign-in email page and use the form.', 'amazing-security' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_login_notice_save' );
		update_option( Decision::OPTION, self::postedFlag() );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-login-notice' ) );
		exit;
	}

	public static function status( string $flag ): string {
		if ( '1' === $flag ) {
			return __( 'Sign-in email is on.', 'amazing-security' );
		}
		return __( 'Sign-in email is off.', 'amazing-security' );
	}

	private static function postedFlag(): string {
		// Nonce is checked in save() before this runs.
		$raw = isset( $_POST[ Decision::OPTION ] ) ? sanitize_text_field( wp_unslash( $_POST[ Decision::OPTION ] ) ) : '0'; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in save().
		return Decision::flag( is_string( $raw ) ? $raw : '0' );
	}

	private static function stored(): string {
		$value = get_option( Decision::OPTION, '0' );
		return is_string( $value ) ? $value : '0';
	}

	private static function postRequest(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return 'post' === $method;
	}
}
