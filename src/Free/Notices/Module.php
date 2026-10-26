<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Notices;

defined( 'ABSPATH' ) || exit;

/** Event email. Off until an administrator turns it on. */
final class Module {
	public static function boot(): void {
		add_option( Notice::OPTION, '0' );
		add_action( 'set_user_role', array( self::class, 'role' ), 10, 3 );
		add_action( 'wp_login_failed', array( self::class, 'limited' ), 10, 2 );
		add_action( 'admin_post_amsec_event_mail', array( self::class, 'save' ) );
	}

	public static function role( int $id, string $role, mixed $old ): void {
		if ( 'administrator' !== $role || ( is_array( $old ) && in_array( 'administrator', $old, true ) ) ) {
			return;
		}
		$user  = function_exists( 'get_userdata' ) ? get_userdata( $id ) : false;
		$login = $user instanceof \WP_User ? $user->user_login : '';
		self::send( 'administrator', is_string( $login ) ? $login : '' );
	}

	public static function limited( string $username, mixed $error ): void {
		unset( $username );
		if ( ! $error instanceof \WP_Error || ! in_array( 'amsec_rate_limited', $error->get_error_codes(), true ) ) {
			return;
		}
		self::send( 'limited', '' );
	}

	public static function form(): void {
		$on = '1' === Notice::flag( get_option( Notice::OPTION, '0' ) );
		echo '<h2 id="amsec-event-mail">' . esc_html__( 'Email for account changes', 'amazing-security-scanner' ) . '</h2>';
		echo '<p>' . esc_html__( 'Off until you turn it on. The site administrator gets an email when an account is given the administrator role, or when the local repeat check limits a sign-in. The message names the account login. It does not include an address or a password.', 'amazing-security-scanner' ) . '</p>';
		if ( ! is_ssl() ) {
			echo '<p>' . esc_html__( 'Open this page over HTTPS to change this email.', 'amazing-security-scanner' ) . '</p>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_event_mail">';
		wp_nonce_field( 'amsec_event_mail' );
		echo '<p><label><input type="checkbox" name="' . esc_attr( Notice::OPTION ) . '" value="1"' . checked( $on, true, false ) . '> ';
		echo esc_html__( 'Send that email', 'amazing-security-scanner' );
		echo '</label></p>';
		submit_button( __( 'Save event email', 'amazing-security-scanner' ) );
		echo '</form>';
	}

	public static function save(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) || ! is_ssl() ) {
			wp_die( esc_html__( 'HTTPS and administrator access are required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_event_mail' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$raw = isset( $_POST[ Notice::OPTION ] ) ? sanitize_text_field( wp_unslash( $_POST[ Notice::OPTION ] ) ) : '0';
		update_option( Notice::OPTION, Notice::flag( is_string( $raw ) ? $raw : '0' ), false );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-settings#amsec-event-mail' ) ) );
		exit;
	}

	private static function send( string $kind, string $login ): void {
		if ( ! function_exists( 'wp_mail' ) ) {
			return;
		}
		$message = Notice::message( Notice::flag( get_option( Notice::OPTION, '0' ) ), $kind, $login );
		if ( null === $message ) {
			return;
		}
		$to = get_option( 'admin_email' );
		if ( ! is_string( $to ) || ! is_email( $to ) || ! self::room() ) {
			return;
		}
		wp_mail( $to, $message['subject'], $message['body'] );
	}

	private static function room(): bool {
		$count = get_transient( 'amsec_event_mail_count' );
		$count = is_numeric( $count ) ? (int) $count : 0;
		if ( $count >= 5 ) {
			return false;
		}
		set_transient( 'amsec_event_mail_count', (string) ( $count + 1 ), HOUR_IN_SECONDS );
		return true;
	}
}
