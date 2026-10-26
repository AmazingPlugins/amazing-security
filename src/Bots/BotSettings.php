<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Bots;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Activity\ActivityHooks;
use AmazingPlugins\Security\Activity\ActivityRepository;
use AmazingPlugins\Security\Admin\FixApprovalAction;
use AmazingPlugins\Security\Sessions\SessionPolicy;

final class BotSettings {
	public function register(): void {
		add_submenu_page( 'amazing-security', __( 'Native bot controls', 'amazing-security-scanner' ), __( 'Bot controls', 'amazing-security-scanner' ), 'manage_options', 'amsec-bots', array( $this, 'render' ) );
	}

	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before changing settings.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), in_array( $mode, array( 'off', 'observe', 'block' ), true ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval and acknowledgement are required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_bot_settings' );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		update_option( 'amsec_bot_mode', $mode, false );
		if ( get_option( 'amsec_bot_mode', 'off' ) !== $mode ) {
			wp_die( esc_html__( 'The setting change could not be verified.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, $mode );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-traffic-guard#bots' ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$mode      = ( new BotHooks() )->mode();
		$available = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->available();
		$label     = match ( $mode ) {
			'observe' => __( 'Observe', 'amazing-security-scanner' ),
			'block' => __( 'Limit', 'amazing-security-scanner' ),
			default => __( 'Off', 'amazing-security-scanner' ),
		};
		echo '<div class="wrap amazing-security-admin amsec-brief">';
		echo '<h1>' . esc_html__( 'Comments and registration', 'amazing-security-scanner' ) . '</h1>';
		echo '<p class="amsec-brief-status"><span class="amsec-pill' . ( 'off' === $mode ? ' is-off' : ' is-on' ) . '">' . esc_html( $label ) . '</span>';
		echo esc_html__( 'Guest comments and new accounts.', 'amazing-security-scanner' ) . ' ';
		self::tip( __( 'Off leaves them alone. Observe counts them. Limit refuses a filled hidden field, or more than the numbers below.', 'amazing-security-scanner' ) );
		echo '</p><ul class="amsec-facts">';
		echo '<li><strong>20</strong> ' . esc_html__( 'guest comments in 5 minutes', 'amazing-security-scanner' ) . ' ';
		self::tip( __( 'Counts comments from people who are not signed in, on the WordPress comment form.', 'amazing-security-scanner' ) );
		echo '</li><li><strong>5</strong> ' . esc_html__( 'registrations in 15 minutes', 'amazing-security-scanner' ) . ' ';
		self::tip( __( 'Counts new accounts on the WordPress registration form.', 'amazing-security-scanner' ) );
		echo '</li><li>' . esc_html__( 'Count storage:', 'amazing-security-scanner' ) . ' <strong>' . esc_html( $available ? __( 'Ready', 'amazing-security-scanner' ) : __( 'Unavailable', 'amazing-security-scanner' ) ) . '</strong> ';
		self::tip( __( 'Ready means a count can be stored. Unavailable means the count is skipped and the hidden-field check still runs.', 'amazing-security-scanner' ) );
		echo '</li></ul>';
		echo '<details class="amsec-more"><summary>' . esc_html__( 'See more', 'amazing-security-scanner' ) . '</summary>';
		echo '<p>' . esc_html__( 'This covers the WordPress comment form and registration on wp-login.php. People who are already signed in are left alone. WooCommerce, Contact Form 7, and custom forms are outside this.', 'amazing-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'The site stores a salted key for the address, not the address, the name, or the comment. Forwarded headers are ignored unless trusted proxies are on. A shared network can group visitors. Storage holds 10,000 keys, and old rows are removed after a day.', 'amazing-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'Recovery command: wp amazing-security bots disable', 'amazing-security-scanner' ) . '</p></details>';
		if ( ! is_ssl() ) {
			echo '<p class="amsec-brief-note">' . esc_html__( 'Use HTTPS to change this mode.', 'amazing-security-scanner' ) . '</p></div>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_bot_settings"><label>' . esc_html__( 'Mode', 'amazing-security-scanner' ) . ' <select name="mode">';
		$choices = array(
			'off'     => __( 'Off', 'amazing-security-scanner' ),
			'observe' => __( 'Observe', 'amazing-security-scanner' ),
			'block'   => __( 'Limit', 'amazing-security-scanner' ),
		);
		foreach ( $choices as $value => $choice ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( $choice ) . '</option>';
		}
		echo '</select></label>';
		wp_nonce_field( 'amsec_bot_settings' );
		echo '<p><label>' . esc_html__( 'Your password', 'amazing-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand Limit can refuse a real visitor who shares an address, or a browser that fills the hidden field.', 'amazing-security-scanner' ) . '</label></p>';
		submit_button( __( 'Approve mode', 'amazing-security-scanner' ), 'secondary' );
		echo '</form></div>';
	}

	private static function tip( string $text ): void {
		static $n = 0;
		++$n;
		$id = 'amsec-bot-tip-' . $n;
		echo '<span class="amsec-tip"><button type="button" class="amsec-tip-button" aria-describedby="' . esc_attr( $id ) . '">' . esc_html__( 'Details', 'amazing-security-scanner' ) . '</button>';
		echo '<span class="amsec-tip-bubble" id="' . esc_attr( $id ) . '" role="tooltip">' . esc_html( $text ) . '</span></span>';
	}

	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}
		update_option( 'amsec_bot_mode', 'off', false );
		update_option( ScannerGuard::OPTION, 'off', false );
		update_option( RateLimiter::OPTION, array( 'mode' => 'off' ) + RateLimiter::settings(), true );
		if ( 'off' !== get_option( 'amsec_bot_mode', 'off' ) || 'off' !== ScannerGuard::mode() || 'off' !== RateLimiter::settings()['mode'] ) {
			\WP_CLI::error( 'Bot controls could not be disabled.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, 'off' );
		\WP_CLI::success( 'Native bot controls, the scanner guard and rate limiting are off.' );
	}
}
