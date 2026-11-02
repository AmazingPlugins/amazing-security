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
		add_submenu_page( 'ironlatch-security-scanner', __( 'Native bot controls', 'ironlatch-security-scanner' ), __( 'Bot controls', 'ironlatch-security-scanner' ), 'manage_options', 'ironlatch-bots', array( $this, 'render' ) );
	}

	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified before changing settings.
		$post   = wp_unslash( $_POST );
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$auth   = wp_parse_auth_cookie( '', is_ssl() ? 'secure_auth' : 'auth' );
		$mode   = is_string( $post['mode'] ?? null ) ? $post['mode'] : '';
		if ( ! SessionPolicy::allowed( 'post' === $method, current_user_can( 'manage_options' ), in_array( $mode, array( 'off', 'observe', 'block' ), true ), FixApprovalAction::cookieAuthenticated() && SessionPolicy::matchingTokens( is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token() ), is_ssl(), '1' === ( $post['confirm'] ?? null ) ) ) {
			wp_die( esc_html__( 'Secure administrator approval and acknowledgement are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'ironlatch_bot_settings' );
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		$user     = wp_get_current_user();
		if ( '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_die( esc_html__( 'Password confirmation failed.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		update_option( 'ironlatch_bot_mode', $mode, false );
		if ( get_option( 'ironlatch_bot_mode', 'off' ) !== $mode ) {
			wp_die( esc_html__( 'The setting change could not be verified.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, $mode );
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-traffic-guard#bots' ) ) );
		exit;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$mode      = ( new BotHooks() )->mode();
		$available = ( new BotCounterStore( $GLOBALS['wpdb'] ) )->available();
		$label     = match ( $mode ) {
			'observe' => __( 'Observe', 'ironlatch-security-scanner' ),
			'block' => __( 'Limit', 'ironlatch-security-scanner' ),
			default => __( 'Off', 'ironlatch-security-scanner' ),
		};
		echo '<div class="wrap ironlatch-security-scanner-admin ironlatch-brief">';
		echo '<h1>' . esc_html__( 'Comments and registration', 'ironlatch-security-scanner' ) . '</h1>';
		echo '<p class="ironlatch-brief-status"><span class="ironlatch-pill' . ( 'off' === $mode ? ' is-off' : ' is-on' ) . '">' . esc_html( $label ) . '</span>';
		echo esc_html__( 'Guest comments and new accounts.', 'ironlatch-security-scanner' ) . ' ';
		self::tip( __( 'Off leaves them alone. Observe counts them. Limit refuses a filled hidden field, or more than the numbers below.', 'ironlatch-security-scanner' ) );
		echo '</p><ul class="ironlatch-facts">';
		echo '<li><strong>20</strong> ' . esc_html__( 'guest comments in 5 minutes', 'ironlatch-security-scanner' ) . ' ';
		self::tip( __( 'Counts comments from people who are not signed in, on the WordPress comment form.', 'ironlatch-security-scanner' ) );
		echo '</li><li><strong>5</strong> ' . esc_html__( 'registrations in 15 minutes', 'ironlatch-security-scanner' ) . ' ';
		self::tip( __( 'Counts new accounts on the WordPress registration form.', 'ironlatch-security-scanner' ) );
		echo '</li><li>' . esc_html__( 'Count storage:', 'ironlatch-security-scanner' ) . ' <strong>' . esc_html( $available ? __( 'Ready', 'ironlatch-security-scanner' ) : __( 'Unavailable', 'ironlatch-security-scanner' ) ) . '</strong> ';
		self::tip( __( 'Ready means a count can be stored. Unavailable means the count is skipped and the hidden-field check still runs.', 'ironlatch-security-scanner' ) );
		echo '</li></ul>';
		echo '<details class="ironlatch-more"><summary>' . esc_html__( 'See more', 'ironlatch-security-scanner' ) . '</summary>';
		echo '<p>' . esc_html__( 'This covers the WordPress comment form and registration on wp-login.php. People who are already signed in are left alone. WooCommerce, Contact Form 7, and custom forms are outside this.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'The site stores a salted key for the address, not the address, the name, or the comment. Forwarded headers are ignored unless trusted proxies are on. A shared network can group visitors. Storage holds 10,000 keys, and old rows are removed after a day.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'Recovery command: wp ironlatch-security-scanner bots disable', 'ironlatch-security-scanner' ) . '</p></details>';
		if ( ! is_ssl() ) {
			echo '<p class="ironlatch-brief-note">' . esc_html__( 'Use HTTPS to change this mode.', 'ironlatch-security-scanner' ) . '</p></div>';
			return;
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="ironlatch_bot_settings"><label>' . esc_html__( 'Mode', 'ironlatch-security-scanner' ) . ' <select name="mode">';
		$choices = array(
			'off'     => __( 'Off', 'ironlatch-security-scanner' ),
			'observe' => __( 'Observe', 'ironlatch-security-scanner' ),
			'block'   => __( 'Limit', 'ironlatch-security-scanner' ),
		);
		foreach ( $choices as $value => $choice ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $mode, $value, false ) . '>' . esc_html( $choice ) . '</option>';
		}
		echo '</select></label>';
		wp_nonce_field( 'ironlatch_bot_settings' );
		echo '<p><label>' . esc_html__( 'Your password', 'ironlatch-security-scanner' ) . ' <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand Limit can refuse a real visitor who shares an address, or a browser that fills the hidden field.', 'ironlatch-security-scanner' ) . '</label></p>';
		submit_button( __( 'Approve mode', 'ironlatch-security-scanner' ), 'secondary' );
		echo '</form></div>';
	}

	private static function tip( string $text ): void {
		static $n = 0;
		++$n;
		$id = 'ironlatch-bot-tip-' . $n;
		echo '<span class="ironlatch-tip"><button type="button" class="ironlatch-tip-button" aria-describedby="' . esc_attr( $id ) . '">' . esc_html__( 'Details', 'ironlatch-security-scanner' ) . '</button>';
		echo '<span class="ironlatch-tip-bubble" id="' . esc_attr( $id ) . '" role="tooltip">' . esc_html( $text ) . '</span></span>';
	}

	public function recovery( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' );
		}
		update_option( 'ironlatch_bot_mode', 'off', false );
		update_option( ScannerGuard::OPTION, 'off', false );
		update_option( RateLimiter::OPTION, array( 'mode' => 'off' ) + RateLimiter::settings(), true );
		if ( 'off' !== get_option( 'ironlatch_bot_mode', 'off' ) || 'off' !== ScannerGuard::mode() || 'off' !== RateLimiter::settings()['mode'] ) {
			\WP_CLI::error( 'Bot controls could not be disabled.' );
		}
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'bot_policy_changed', 0, 'off' );
		\WP_CLI::success( 'Native bot controls, the scanner guard and rate limiting are off.' );
	}
}
