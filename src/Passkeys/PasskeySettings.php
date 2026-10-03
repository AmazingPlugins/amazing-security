<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Proxy\FreshSecurityOptions;
use AmazingPlugins\Security\Activity\{ActivityHooks, ActivityRepository};
final class PasskeySettings {
	private function service(): PasskeySettingsService {
		return new PasskeySettingsService( new FreshSecurityOptions( $GLOBALS['wpdb'], new WordPressOptions() ) );
	}
	public function register(): void {
		$hook = add_submenu_page( 'amazing-security', __( 'Passkeys', 'amazing-security' ), __( 'Passkeys', 'amazing-security' ), 'manage_options', 'amsec-passkeys', array( $this, 'render' ) );
		add_action(
			'admin_enqueue_scripts',
			static function ( string $current ) use ( $hook ): void {
				if ( $current === $hook ) {
					wp_enqueue_style( 'amazing-security-admin', plugins_url( 'assets/admin.css', AMAZING_SECURITY_FILE ), array(), '0.1.0' ); }
			}
		);
	}
	public function handle(): void {
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact-current-policy nonce and matched native session are checked below before mutation.
		$post     = wp_unslash( $_POST );
		$server   = array(
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exact method comparison rejects transformed or suffix matches.
			'REQUEST_METHOD' => isset( $_SERVER['REQUEST_METHOD'] ) ? wp_unslash( $_SERVER['REQUEST_METHOD'] ) : null,
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Exact origin comparison rejects transformed or suffix matches.
			'HTTP_ORIGIN'    => isset( $_SERVER['HTTP_ORIGIN'] ) ? wp_unslash( $_SERVER['HTTP_ORIGIN'] ) : null,
		);
		$context  = ( new PasskeyRuntime( $GLOBALS['wpdb'] ) )->context();
		$id       = get_current_user_id();
		$auth     = wp_parse_auth_cookie( '', 'secure_auth' );
		$cookieId = wp_validate_auth_cookie( '', 'secure_auth' );
		$loggedId = wp_validate_auth_cookie( '', 'logged_in' );
		try {
			$service = $this->service();
			$state   = $service->status();
			$fp      = $service->fingerprint();
		} catch ( \Throwable ) {
			$this->deny();
			return; }
		$nonce = is_string( $post['_wpnonce'] ?? null ) && strlen( $post['_wpnonce'] ) <= 64 && false !== wp_verify_nonce( $post['_wpnonce'], 'amsec_passkey_policy_' . $fp );
		if ( null === $context || ! PasskeyRequestGate::request( $context, $server, is_ssl() ) || $loggedId !== $id || ! PasskeyRequestGate::own( $id, is_int( $cookieId ) ? $cookieId : 0, is_array( $auth ) ? (string) $auth['token'] : '', wp_get_session_token(), current_user_can( 'manage_options' ), $nonce ) || ! empty( $state['invalid'] ) || ( $post['fingerprint'] ?? null ) !== $fp || ! in_array( $post['enabled'] ?? null, array( '0', '1' ), true ) || '1' !== ( $post['confirm'] ?? null ) ) {
			$this->deny();
			return; }
		$password = is_string( $post['password'] ?? null ) && strlen( $post['password'] ) <= 1024 ? $post['password'] : '';
		clean_user_cache( $id );
		$user = get_userdata( $id );
		if ( '' === $password || ! $user instanceof \WP_User || ! wp_check_password( $password, $user->user_pass, $id ) ) {
			$this->deny();
			return; }
		try {
			$saved = $service->apply( $fp, '1' === $post['enabled'], $context );
		} catch ( \Throwable ) {
			$saved = 'failed'; }
		if ( 'saved' !== $saved ) {
			$this->deny();
			return; }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, '1' === $post['enabled'] ? 'passkeys-on' : 'passkeys-off' );
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-passkeys' ) );
		exit;
	}
	private function deny(): void {
		wp_die( esc_html__( 'A current HTTPS administrator session, matching policy approval and password are required. Reload this page before trying again.', 'amazing-security' ), '', array( 'response' => 403 ) );
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amazing-security' ), '', array( 'response' => 403 ) );
			return; }
		echo '<div class="wrap amazing-security-admin"><header class="amsec-header"><div><h1>' . esc_html__( 'Passkeys', 'amazing-security' ) . '</h1><p>' . esc_html__( 'Let people sign in with a device they already trust.', 'amazing-security' ) . '</p></div></header>';
		echo '<section class="amsec-overview"><h2>' . esc_html__( 'Your site, your sign-in keys', 'amazing-security' ) . '</h2><p>' . esc_html__( 'Passkeys use the device’s screen lock, fingerprint or face recognition. This site stores public keys; private keys stay with the authenticator or its sync provider. No Amazing Plugins server is involved.', 'amazing-security' ) . '</p><p>' . esc_html__( 'People add up to five passkeys from their own WordPress profile. The passkey is the sign-in. Use the verification code with the password to add or remove a passkey, and to sign in with a password. A locked account or a required password reset still blocks a passkey.', 'amazing-security' ) . '</p><p><a class="button button-secondary" href="' . esc_url( get_edit_profile_url( get_current_user_id() ) . '#amsec-passkeys' ) . '">' . esc_html__( 'Manage your passkeys', 'amazing-security' ) . '</a></p></section>';
		try {
			$service = $this->service();
			$state   = $service->status();
			$fp      = $service->fingerprint();
		} catch ( \Throwable ) {
			$state = array( 'invalid' => true ); }
		if ( ! empty( $state['invalid'] ) ) {
			echo '<section class="amsec-file-scan"><p>' . esc_html__( 'Passkey settings could not be read. Use host recovery to turn the feature off before approving a new policy.', 'amazing-security' ) . '</p></section>'; } else {
				echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'Site availability', 'amazing-security' ) . '</h2><p>' . esc_html( $state['enabled'] ? __( 'Passkeys are enabled in site settings.', 'amazing-security' ) : __( 'Passkeys are off. Password sign-in is available.', 'amazing-security' ) ) . '</p>';
				$context = ( new PasskeyRuntime( $GLOBALS['wpdb'] ) )->context();
			if ( defined( 'AMSEC_DISABLE_PASSKEYS' ) && AMSEC_DISABLE_PASSKEYS ) {
				echo '<p>' . esc_html__( 'The host has paused passkey sign-in and enrollment.', 'amazing-security' ) . '</p>'; }
			if ( null === $context || ! is_ssl() ) {
					echo '<p>' . esc_html__( 'Set the WordPress address to a supported HTTPS domain and open this page over HTTPS to approve changes.', 'amazing-security' ) . '</p>'; } else {
				if ( ! PasskeyVerifier::available() ) {
					echo '<p>' . esc_html__( 'This host is missing a required passkey capability. Password sign-in is available.', 'amazing-security' ) . '</p>'; }
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_passkey_settings"><input type="hidden" name="fingerprint" value="' . esc_attr( $fp ) . '"><p><label>' . esc_html__( 'Passkey sign-in', 'amazing-security' ) . ' <select name="enabled"><option value="0"' . selected( false, $state['enabled'], false ) . '>' . esc_html__( 'Off', 'amazing-security' ) . '</option><option value="1"' . selected( true, $state['enabled'], false ) . '>' . esc_html__( 'On', 'amazing-security' ) . '</option></select></label></p>';
				wp_nonce_field( 'amsec_passkey_policy_' . $fp );
				echo '<p><label>' . esc_html__( 'Your password', 'amazing-security' ) . ' <input type="password" name="password" autocomplete="current-password" maxlength="1024" required></label></p><p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I approve this sign-in setting and know how to recover access.', 'amazing-security' ) . '</label></p>';
				submit_button( __( 'Approve passkey setting', 'amazing-security' ), 'secondary' );
				echo '</form>';
					}
							echo '</section>';
			}
			echo '<section class="amsec-file-scan"><h2>' . esc_html__( 'If a device is lost', 'amazing-security' ) . '</h2><p>' . esc_html__( 'Use your password and existing verification code, or the WordPress password-reset flow. Remove the lost device from your profile after signing in. Turning this feature off keeps saved keys but stops passkey sign-in and enrollment.', 'amazing-security' ) . '</p><p>' . esc_html__( 'This release supports the native WordPress login page. Changing the site address requires new passkeys. Device and sync-provider compatibility still needs testing.', 'amazing-security' ) . '</p><details><summary>' . esc_html__( 'Host recovery commands', 'amazing-security' ) . '</summary><p><code>wp amazing-security passkeys disable</code><br><code>wp amazing-security passkeys revoke USER_ID</code></p><p>' . esc_html__( 'The AMSEC_DISABLE_PASSKEYS constant also pauses sign-in and enrollment. It does not remove existing verification requirements.', 'amazing-security' ) . '</p></details></section></div>';
	}
	public function recoveryDisable( array $args, array $assoc ): void {
		if ( array() !== $args || array() !== $assoc ) {
			\WP_CLI::error( 'This command accepts no arguments.' ); }
		if ( ! $this->service()->disable() ) {
			\WP_CLI::error( 'Passkeys could not be disabled.' ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', 0, 'passkeys-off' );
		\WP_CLI::success( 'Passkey sign-in and enrollment are off. Saved credentials are retained.' );
	}
	public function recoveryRevoke( array $args, array $assoc ): void {
		if ( count( $args ) !== 1 || array() !== $assoc || ! ctype_digit( (string) $args[0] ) || (int) $args[0] < 1 || ! get_userdata( (int) $args[0] ) ) {
			\WP_CLI::error( 'Pass one existing user ID.' ); }
		if ( ! ( new PasskeyRepository( $GLOBALS['wpdb'] ) )->revokeUser( (int) $args[0] ) ) {
			\WP_CLI::error( 'Passkeys could not be revoked.' ); }
		( new ActivityHooks( new ActivityRepository( $GLOBALS['wpdb'] ) ) )->record( 'security_setting_changed', (int) $args[0], 'passkeys-revoked' );
		\WP_CLI::success( 'Saved passkeys and pending enrollments removed for the selected account.' );
	}
}
