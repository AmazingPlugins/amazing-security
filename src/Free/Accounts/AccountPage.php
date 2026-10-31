<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\ScreenTabs;
use AmazingPlugins\Security\Login\AuthFactorDetector;
use AmazingPlugins\Security\Login\AuthFactorPanel;
use AmazingPlugins\Security\Login\RequiredTotpPage;
use AmazingPlugins\Security\Free\LoginNotice\Page as LoginNoticePage;
use AmazingPlugins\Security\Free\PasswordRules\Page as PasswordRulesPage;
use AmazingPlugins\Security\Sessions\SessionPage;

/** Account protection screen. Saving never turns on the common-password switch. */
final class AccountPage {
	public static function menu(): void {
		add_submenu_page(
			'amazing-security',
			__( 'Log In & Register', 'amsec-security-scanner' ),
			__( 'Log In & Register', 'amsec-security-scanner' ),
			'manage_options',
			'amsec-accounts',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$idle      = IdleLogout::minutes( self::stored( IdleLogout::OPTION ) );
		$approval  = Settings::flag( self::stored( RegistrationApproval::OPTION ) );
		$email     = Settings::flag( self::stored( EmailFactor::OPTION ) );
		$challenge = Settings::flag( self::stored( LoginChallenge::OPTION ) );
		$rate      = LoginExtras::rate( self::stored( LoginExtras::RATE ) ) ?? 'off';
		$xmlrpc    = LoginExtras::xmlrpc( self::stored( LoginExtras::XMLRPC ) ) ?? '0';
		$erase     = Settings::flag( self::stored( Settings::ERASE ) );
		echo '<div class="wrap amazing-security-admin">';
		ScreenTabs::bar(
			array(
				'sign-in'        => __( 'Sign-in', 'amsec-security-scanner' ),
				'password-rules' => __( 'Password rules', 'amsec-security-scanner' ),
				'sessions'       => __( 'Sessions', 'amsec-security-scanner' ),
				'sign-in-email'  => __( 'Sign-in email', 'amsec-security-scanner' ),
				'verification'   => __( 'Verification', 'amsec-security-scanner' ),
				'passkeys'       => __( 'Passkeys', 'amsec-security-scanner' ),
			)
		);
		ScreenTabs::panel( 'sign-in', true );
		echo '<p>' . esc_html__( 'These stay off until you save them. Saving here does not mean the site is clean.', 'amsec-security-scanner' ) . '</p>';
		echo '<form class="amsec-auth" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="amsec_accounts_save">';
		wp_nonce_field( 'amsec_accounts_save' );
		echo '<fieldset class="amsec-auth-group"><legend>' . esc_html__( 'Sign-in', 'amsec-security-scanner' ) . '</legend>';
		echo '<div class="amsec-field"><label for="amsec-idle-minutes">' . esc_html__( 'Idle logout', 'amsec-security-scanner' ) . '</label>';
		echo '<select id="amsec-idle-minutes" name="' . esc_attr( IdleLogout::OPTION ) . '">';
		self::choice( '0', (string) $idle, __( 'Off', 'amsec-security-scanner' ) );
		self::choice( '15', (string) $idle, __( '15 minutes', 'amsec-security-scanner' ) );
		self::choice( '30', (string) $idle, __( '30 minutes', 'amsec-security-scanner' ) );
		self::choice( '60', (string) $idle, __( '60 minutes', 'amsec-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Signs someone out of wp-admin after this much quiet time.', 'amsec-security-scanner' ) . '</p></div>';
		self::flagField( RegistrationApproval::OPTION, $approval, __( 'Hold new accounts until an administrator approves them', 'amsec-security-scanner' ) );
		self::flagField( EmailFactor::OPTION, $email, __( 'Email a sign-in code when the account has no authenticator app', 'amsec-security-scanner' ) );
		self::flagField( LoginChallenge::OPTION, $challenge, __( 'Ask for the sum of two numbers on the login form', 'amsec-security-scanner' ) );
		echo '<p>' . esc_html__( 'When this is on, the WordPress login form and a WooCommerce login form ask the question. The answer stays on this site. An outside CAPTCHA service is not connected.', 'amsec-security-scanner' ) . '</p>';
		echo '</fieldset>';
		echo '<fieldset class="amsec-auth-group"><legend>' . esc_html__( 'Sign-in limits', 'amsec-security-scanner' ) . '</legend>';
		echo '<div class="amsec-field"><label for="amsec-login-rate">' . esc_html__( 'Repeated sign-in tries', 'amsec-security-scanner' ) . '</label>';
		echo '<select id="amsec-login-rate" name="' . esc_attr( LoginExtras::RATE ) . '">';
		self::choice( 'off', $rate, __( 'Off', 'amsec-security-scanner' ) );
		self::choice( 'observe', $rate, __( 'Record only', 'amsec-security-scanner' ) );
		self::choice( 'block', $rate, __( 'Limit repeats', 'amsec-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Record only counts failed tries. Limit repeats pauses more tries for a while. A shared address can pause a real person too.', 'amsec-security-scanner' ) . '</p></div>';
		echo '<div class="amsec-field"><label for="amsec-xmlrpc-auth">' . esc_html__( 'Password tries through xmlrpc.php', 'amsec-security-scanner' ) . '</label>';
		echo '<select id="amsec-xmlrpc-auth" name="' . esc_attr( LoginExtras::XMLRPC ) . '">';
		self::choice( '0', $xmlrpc, __( 'Allowed', 'amsec-security-scanner' ) );
		self::choice( '1', $xmlrpc, __( 'Turned off', 'amsec-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Turned off stops password tries through xmlrpc.php. Pingbacks stay separate. Some apps still need this allowed.', 'amsec-security-scanner' ) . '</p></div>';
		echo '</fieldset>';
		echo '<fieldset class="amsec-auth-group"><legend>' . esc_html__( 'Uninstall', 'amsec-security-scanner' ) . '</legend>';
		self::flagField( Settings::ERASE, $erase, __( 'Erase all AmSec Security Scanner settings, logs and scan results when the plugin is deleted', 'amsec-security-scanner' ) );
		echo '<p>' . esc_html__( 'Leave this off to keep your settings if you reinstall later.', 'amsec-security-scanner' ) . '</p>';
		echo '</fieldset>';
		submit_button( __( 'Save account protection', 'amsec-security-scanner' ) );
		echo '</form>';
		if ( '1' === $approval ) {
			echo '<section class="amsec-auth-group"><h2>' . esc_html__( 'New accounts', 'amsec-security-scanner' ) . '</h2>';
			echo '<p>' . esc_html__( 'These people registered and cannot sign in until you approve them.', 'amsec-security-scanner' ) . '</p>';
			self::pendingList();
			echo '</section>';
		}
		ScreenTabs::close();
		ScreenTabs::panel( 'password-rules', false );
		( new PasswordRulesPage() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'sessions', false );
		( new SessionPage() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'sign-in-email', false );
		LoginNoticePage::render();
		ScreenTabs::close();
		ScreenTabs::panel( 'verification', false );
		( new RequiredTotpPage() )->render();
		ScreenTabs::close();
		ScreenTabs::panel( 'passkeys', false );
		self::passkeys();
		ScreenTabs::close();
		echo '</div>';
	}

	public static function save(): void {
		self::guard( 'amsec_accounts_save' );
		$post = array();
		foreach ( array_keys( Settings::fromPost( array() ) ) as $key ) {
			$post[ $key ] = self::posted( $key );
		}
		foreach ( Settings::fromPost( $post ) as $key => $value ) {
			update_option( $key, $value );
		}
		$rate = LoginExtras::rate( self::posted( LoginExtras::RATE ) );
		if ( null !== $rate ) {
			update_option( LoginExtras::RATE, $rate );
		}
		$xmlrpc = LoginExtras::xmlrpc( self::posted( LoginExtras::XMLRPC ) );
		if ( null !== $xmlrpc ) {
			update_option( LoginExtras::XMLRPC, $xmlrpc );
		}
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=amsec-accounts#sign-in' ) ) );
		exit;
	}

	public static function approve(): void {
		self::requirePost();
		// The nonce name includes this id, so the id is read before the check.
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		check_admin_referer( 'amsec_accounts_approve_' . $user_id );
		if ( $user_id > 0 && get_userdata( $user_id ) ) {
			delete_user_meta( $user_id, RegistrationApproval::META );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-accounts' ) );
		exit;
	}

	public static function idleText( int $minutes ): string {
		if ( ! in_array( $minutes, array( 15, 30, 60 ), true ) ) {
			return __( 'Idle logout is off.', 'amsec-security-scanner' );
		}
		return sprintf(
			/* translators: %d: idle minutes */
			__( 'Idle logout is on at %d minutes.', 'amsec-security-scanner' ),
			$minutes
		);
	}

	private static function choice( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '"' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}

	private static function flagField( string $name, string $current, string $label ): void {
		echo '<label class="amsec-check"><input type="checkbox" name="' . esc_attr( $name ) . '" value="1"' . checked( '1', $current, false ) . '> <span>' . esc_html( $label ) . '</span></label>';
	}

	private static function pendingList(): void {
		$users = get_users(
			array(
				'meta_key'   => RegistrationApproval::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- A bounded list of accounts waiting for approval.
				'meta_value' => '1', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- A bounded list of accounts waiting for approval.
				'number'     => 100,
				'orderby'    => 'ID',
				'order'      => 'ASC',
			)
		);
		if ( ! is_array( $users ) || array() === $users ) {
			echo '<p>' . esc_html__( 'No new accounts are waiting for you.', 'amsec-security-scanner' ) . '</p>';
			return;
		}
		echo '<ul>';
		foreach ( $users as $account ) {
			if ( ! $account instanceof \WP_User ) {
				continue;
			}
			echo '<li>' . esc_html( $account->user_login ) . ' ';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
			echo '<input type="hidden" name="action" value="amsec_accounts_approve">';
			echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $account->ID ) . '">';
			wp_nonce_field( 'amsec_accounts_approve_' . $account->ID );
			submit_button( __( 'Approve', 'amsec-security-scanner' ), 'secondary', 'submit', false );
			echo '</form></li>';
		}
		echo '</ul>';
	}

	private static function passkeys(): void {
		$factor = AuthFactorDetector::fromWordPress()->passkeys( get_current_user_id() );
		$url    = RequiredTotpPage::directoryUrl( (string) ( $factor['suggest_slug'] ?? 'two-factor' ) );
		echo '<p>' . esc_html__( 'AmSec Security Scanner reports whether a passkey plugin is present. It does not enroll devices.', 'amsec-security-scanner' ) . '</p>';
		echo wp_kses( AuthFactorPanel::html( __( 'Passkeys', 'amsec-security-scanner' ), $factor, $url, 'passkeys' ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
	}

	private static function guard( string $nonce ): void {
		self::requirePost();
		check_admin_referer( $nonce );
	}

	private static function requirePost(): void {
		if ( ! self::postRequest() ) {
			wp_die( esc_html__( 'Open the account protection page and use the form.', 'amsec-security-scanner' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
	}

	private static function postRequest(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return 'post' === $method;
	}

	private static function posted( string $key ): string {
		// Nonce is checked in guard() before this runs.
		$raw = isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '0'; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked in guard().
		return is_string( $raw ) ? $raw : '0';
	}

	private static function stored( string $key ): string {
		$value = get_option( $key, '0' );
		return is_string( $value ) ? $value : '0';
	}
}
