<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Login\RecoveryCodes;
use AmazingPlugins\Security\Login\SecretCipher;
use AmazingPlugins\Security\Login\Totp;
use AmazingPlugins\Security\Login\TotpEnrollment;
use AmazingPlugins\Security\Login\WordPressPendingEnrollmentStore;
use AmazingPlugins\Security\Login\WordPressTotpStore;

final class TotpAction {
	public static function canManage( int $userId, int $currentId, bool $hasCapability, bool $https ): bool {
		return $userId > 0 && $userId === $currentId && $hasCapability && $https;
	}

	public function begin(): void {
		$userId = $this->authorize( 'amsec_totp_begin' );
		$result = $this->enrollment()->begin( $userId, is_ssl() );
		if ( ! $result->allowed ) {
			$this->refuse();
		}
		$uri   = 'otpauth://totp/' . rawurlencode( 'Amazing Security:' . wp_get_current_user()->user_login ) . '?secret=' . rawurlencode( $result->secretBase32 ) . '&issuer=Amazing%20Security&algorithm=SHA1&digits=6&period=30';
		$html  = '<p>Enter this secret in your authenticator app, then type its current six-digit code. This setup expires in five minutes.</p><p><code>' . esc_html( $result->secretBase32 ) . '</code></p><p><a href="' . esc_attr( $uri ) . '">Open in authenticator app</a></p>';
		$html .= '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="amsec_totp_confirm"><input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'amsec_totp_confirm' ) ) . '"><label>Current code <input name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required></label> <button class="button button-primary" type="submit">Confirm and show recovery codes</button></form>';
		$this->page( 'Set up administrator verification', $html );
	}

	public function confirm(): void {
		$userId = $this->authorize( 'amsec_totp_confirm' );
		if ( ! is_ssl() ) {
			$this->refuse();
		}
		// This action already verified its nonce above.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$code  = isset( $_POST['code'] ) && is_string( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$codes = $this->enrollment()->confirm( $userId, $code );
		if ( array() === $codes ) {
			$this->refuse();
		}
		$this->showCodes( $codes );
	}

	public function disable(): void {
		$userId = $this->authorize( 'amsec_totp_disable' );
		if ( null !== ( new \AmazingPlugins\Security\Login\RequiredTotpPolicy() )->generation() ) {
			wp_die( esc_html__( 'Required verification is active. Use an enrolled administrator or host-level recovery to disable the policy first.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		$this->reauthenticate( $userId );
		if ( ! $this->enrollment()->disable( $userId, $this->factor() ) ) {
			$this->refuse();
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amazing-security#amsec-login-title' ) );
		exit;
	}

	public function regenerate(): void {
		$userId = $this->authorize( 'amsec_totp_regenerate' );
		$this->reauthenticate( $userId );
		$codes = $this->enrollment()->regenerate( $userId, $this->factor() );
		if ( array() === $codes ) {
			$this->refuse();
		}
		$this->showCodes( $codes );
	}

	private function authorize( string $action ): int {
		$id    = get_current_user_id();
		$user  = wp_get_current_user();
		$roles = $user instanceof \WP_User && is_array( $user->roles ) ? $user->roles : array();
		if ( ! self::canManage( $id, $id, \AmazingPlugins\Security\Login\RequiredTotpPolicy::coveredAccount( current_user_can( 'manage_options' ), $roles ), is_ssl() ) ) {
			wp_die( esc_html__( 'You cannot change this account.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
		return $id;
	}

	private function reauthenticate( int $userId ): void {
		// Nonce checked by authorize(); password bytes must stay intact for wp_check_password().
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$password = isset( $_POST['password'] ) && is_string( $_POST['password'] ) ? wp_unslash( $_POST['password'] ) : '';
		$user     = get_userdata( $userId );
		if ( ! $user || ! wp_check_password( $password, $user->user_pass, $userId ) ) {
			$this->refuse();
		}
	}

	private function factor(): string {
		// This action already verified its nonce above.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return isset( $_POST['factor'] ) && is_string( $_POST['factor'] ) ? sanitize_text_field( wp_unslash( $_POST['factor'] ) ) : '';
	}

	private function enrollment(): TotpEnrollment {
		return new TotpEnrollment(
			new WordPressTotpStore( $GLOBALS['wpdb'] ),
			new WordPressPendingEnrollmentStore(),
			new SecretCipher( wp_salt( 'auth' ) ),
			new Totp(),
			new RecoveryCodes()
		);
	}

	private function showCodes( array $codes ): void {
		$html = '<p>Save these recovery codes now. They are shown once and each works once.</p><ol>';
		foreach ( $codes as $code ) {
			$html .= '<li><code>' . esc_html( $code ) . '</code></li>';
		}
		$html .= '</ol>';
		$this->page( 'Recovery codes', $html );
	}

	private function page( string $title, string $html ): void {
		nocache_headers();
		$html .= '<p><a href="' . esc_url( admin_url( 'admin.php?page=amazing-security#amsec-login-title' ) ) . '">Return to Amazing Security</a></p>';
		wp_die( $html, esc_html( $title ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All generated dynamic content is escaped above.
	}

	private function refuse(): void {
		wp_die( esc_html__( 'Verification could not be completed. Check the code or start again.', 'amazing-security' ), '', array( 'response' => 400 ) );
	}
}
