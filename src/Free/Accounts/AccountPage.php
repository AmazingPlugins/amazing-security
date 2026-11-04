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
			'ironlatch-security-scanner',
			__( 'Log In & Register', 'ironlatch-security-scanner' ),
			__( 'Log In & Register', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-accounts',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$idle      = IdleLogout::minutes( self::stored( IdleLogout::OPTION ) );
		$approval  = Settings::flag( self::stored( RegistrationApproval::OPTION ) );
		$email     = Settings::flag( self::stored( EmailFactor::OPTION ) );
		$challenge = Settings::flag( self::stored( LoginChallenge::OPTION ) );
		$rate      = LoginExtras::rate( self::stored( LoginExtras::RATE ) ) ?? 'off';
		$xmlrpc    = LoginExtras::xmlrpc( self::stored( LoginExtras::XMLRPC ) ) ?? '0';
		$erase     = Settings::flag( self::stored( Settings::ERASE ) );
		echo '<div class="wrap ironlatch-security-scanner-admin">';
		ScreenTabs::bar(
			array(
				'sign-in'        => __( 'Sign-in', 'ironlatch-security-scanner' ),
				'password-rules' => __( 'Password rules', 'ironlatch-security-scanner' ),
				'sessions'       => __( 'Sessions', 'ironlatch-security-scanner' ),
				'sign-in-email'  => __( 'Sign-in email', 'ironlatch-security-scanner' ),
				'verification'   => __( 'Verification', 'ironlatch-security-scanner' ),
				'passkeys'       => __( 'Passkeys', 'ironlatch-security-scanner' ),
			)
		);
		ScreenTabs::panel( 'sign-in', true );
		echo '<p>' . esc_html__( 'These stay off until you save them. Saving here does not mean the site is clean.', 'ironlatch-security-scanner' ) . '</p>';
		echo '<form class="ironlatch-auth" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="ironlatch_accounts_save">';
		wp_nonce_field( 'ironlatch_accounts_save' );
		echo '<fieldset class="ironlatch-auth-group"><legend>' . esc_html__( 'Sign-in', 'ironlatch-security-scanner' ) . '</legend>';
		echo '<div class="ironlatch-field"><label for="ironlatch-idle-minutes">' . esc_html__( 'Idle logout', 'ironlatch-security-scanner' ) . '</label>';
		echo '<select id="ironlatch-idle-minutes" name="' . esc_attr( IdleLogout::OPTION ) . '">';
		self::choice( '0', (string) $idle, __( 'Off', 'ironlatch-security-scanner' ) );
		self::choice( '15', (string) $idle, __( '15 minutes', 'ironlatch-security-scanner' ) );
		self::choice( '30', (string) $idle, __( '30 minutes', 'ironlatch-security-scanner' ) );
		self::choice( '60', (string) $idle, __( '60 minutes', 'ironlatch-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Signs someone out of wp-admin after this much quiet time.', 'ironlatch-security-scanner' ) . '</p></div>';
		self::flagField( RegistrationApproval::OPTION, $approval, __( 'Hold new accounts until an administrator approves them', 'ironlatch-security-scanner' ) );
		self::flagField( EmailFactor::OPTION, $email, __( 'Email a sign-in code when the account has no authenticator app', 'ironlatch-security-scanner' ) );
		self::flagField( LoginChallenge::OPTION, $challenge, __( 'Ask for the sum of two numbers on the login form', 'ironlatch-security-scanner' ) );
		echo '<p>' . esc_html__( 'When this is on, the WordPress login form and a WooCommerce login form ask the question. The answer stays on this site. An outside CAPTCHA service is not connected.', 'ironlatch-security-scanner' ) . '</p>';
		echo '</fieldset>';
		echo '<fieldset class="ironlatch-auth-group"><legend>' . esc_html__( 'Sign-in limits', 'ironlatch-security-scanner' ) . '</legend>';
		echo '<div class="ironlatch-field"><label for="ironlatch-login-rate">' . esc_html__( 'Repeated sign-in tries', 'ironlatch-security-scanner' ) . '</label>';
		echo '<select id="ironlatch-login-rate" name="' . esc_attr( LoginExtras::RATE ) . '">';
		self::choice( 'off', $rate, __( 'Off', 'ironlatch-security-scanner' ) );
		self::choice( 'observe', $rate, __( 'Record only', 'ironlatch-security-scanner' ) );
		self::choice( 'block', $rate, __( 'Limit repeats', 'ironlatch-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Record only counts failed tries. Limit repeats pauses more tries for a while. A shared address can pause a real person too.', 'ironlatch-security-scanner' ) . '</p></div>';
		echo '<div class="ironlatch-field"><label for="ironlatch-xmlrpc-auth">' . esc_html__( 'Password tries through xmlrpc.php', 'ironlatch-security-scanner' ) . '</label>';
		echo '<select id="ironlatch-xmlrpc-auth" name="' . esc_attr( LoginExtras::XMLRPC ) . '">';
		self::choice( '0', $xmlrpc, __( 'Allowed', 'ironlatch-security-scanner' ) );
		self::choice( '1', $xmlrpc, __( 'Turned off', 'ironlatch-security-scanner' ) );
		echo '</select><p>' . esc_html__( 'Turned off stops password tries through xmlrpc.php. Pingbacks stay separate. Some apps still need this allowed.', 'ironlatch-security-scanner' ) . '</p></div>';
		echo '</fieldset>';
		echo '<fieldset class="ironlatch-auth-group"><legend>' . esc_html__( 'Uninstall', 'ironlatch-security-scanner' ) . '</legend>';
		self::flagField( Settings::ERASE, $erase, __( 'Erase all Ironlatch Security Scanner settings, logs and scan results when the plugin is deleted', 'ironlatch-security-scanner' ) );
		echo '<p>' . esc_html__( 'Leave this off to keep your settings if you reinstall later.', 'ironlatch-security-scanner' ) . '</p>';
		echo '</fieldset>';
		submit_button( __( 'Save account protection', 'ironlatch-security-scanner' ) );
		echo '</form>';
		if ( '1' === $approval ) {
			echo '<section class="ironlatch-auth-group"><h2>' . esc_html__( 'New accounts', 'ironlatch-security-scanner' ) . '</h2>';
			echo '<p>' . esc_html__( 'These people registered and cannot sign in until you approve them.', 'ironlatch-security-scanner' ) . '</p>';
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
		self::requirePost();
		check_admin_referer( 'ironlatch_accounts_save' );
		$post = array();
		foreach ( array_keys( Settings::fromPost( array() ) ) as $key ) {
			$post[ $key ] = isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '0';
		}
		$rate_raw   = isset( $_POST[ LoginExtras::RATE ] ) && is_string( $_POST[ LoginExtras::RATE ] ) ? sanitize_text_field( wp_unslash( $_POST[ LoginExtras::RATE ] ) ) : '0';
		$xmlrpc_raw = isset( $_POST[ LoginExtras::XMLRPC ] ) && is_string( $_POST[ LoginExtras::XMLRPC ] ) ? sanitize_text_field( wp_unslash( $_POST[ LoginExtras::XMLRPC ] ) ) : '0';
		foreach ( Settings::fromPost( $post ) as $key => $value ) {
			update_option( $key, $value );
		}
		$rate = LoginExtras::rate( $rate_raw );
		if ( null !== $rate ) {
			update_option( LoginExtras::RATE, $rate );
		}
		$xmlrpc = LoginExtras::xmlrpc( $xmlrpc_raw );
		if ( null !== $xmlrpc ) {
			update_option( LoginExtras::XMLRPC, $xmlrpc );
		}
		wp_safe_redirect( \AmazingPlugins\Security\Admin\Brand::saved( admin_url( 'admin.php?page=ironlatch-accounts#sign-in' ) ) );
		exit;
	}

	public static function approve(): void {
		self::requirePost();
		check_admin_referer( 'ironlatch_accounts_approve' );
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		if ( $user_id > 0 && get_userdata( $user_id ) ) {
			delete_user_meta( $user_id, RegistrationApproval::META );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-accounts' ) );
		exit;
	}

	public static function idleText( int $minutes ): string {
		if ( ! in_array( $minutes, array( 15, 30, 60 ), true ) ) {
			return __( 'Idle logout is off.', 'ironlatch-security-scanner' );
		}
		return sprintf(
			/* translators: %d: idle minutes */
			__( 'Idle logout is on at %d minutes.', 'ironlatch-security-scanner' ),
			$minutes
		);
	}

	private static function choice( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '"' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}

	private static function flagField( string $name, string $current, string $label ): void {
		echo '<label class="ironlatch-check"><input type="checkbox" name="' . esc_attr( $name ) . '" value="1"' . checked( '1', $current, false ) . '> <span>' . esc_html( $label ) . '</span></label>';
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
			echo '<p>' . esc_html__( 'No new accounts are waiting for you.', 'ironlatch-security-scanner' ) . '</p>';
			return;
		}
		echo '<ul>';
		foreach ( $users as $account ) {
			if ( ! $account instanceof \WP_User ) {
				continue;
			}
			echo '<li>' . esc_html( $account->user_login ) . ' ';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
			echo '<input type="hidden" name="action" value="ironlatch_accounts_approve">';
			echo '<input type="hidden" name="user_id" value="' . esc_attr( (string) $account->ID ) . '">';
			wp_nonce_field( 'ironlatch_accounts_approve' );
			submit_button( __( 'Approve', 'ironlatch-security-scanner' ), 'secondary', 'submit', false );
			echo '</form></li>';
		}
		echo '</ul>';
	}

	private static function passkeys(): void {
		$factor = AuthFactorDetector::fromWordPress()->passkeys( get_current_user_id() );
		$url    = RequiredTotpPage::directoryUrl( (string) ( $factor['suggest_slug'] ?? 'two-factor' ) );
		echo '<p>' . esc_html__( 'Ironlatch Security Scanner reports whether a passkey plugin is present. It does not enroll devices.', 'ironlatch-security-scanner' ) . '</p>';
		echo wp_kses( AuthFactorPanel::html( __( 'Passkeys', 'ironlatch-security-scanner' ), $factor, $url, 'passkeys' ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
	}

	private static function requirePost(): void {
		if ( ! self::postRequest() ) {
			wp_die( esc_html__( 'Open the account protection page and use the form.', 'ironlatch-security-scanner' ), '', array( 'response' => 405 ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
	}

	private static function postRequest(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		return 'post' === $method;
	}

	private static function stored( string $key ): string {
		$value = get_option( $key, '0' );
		return is_string( $value ) ? $value : '0';
	}
}
