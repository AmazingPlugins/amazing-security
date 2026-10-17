<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

/** Code screen after the password is accepted for an account that already has verification. */
final class LoginSecondStep {
	public const COOKIE = 'amsec_login_step';

	public const ERROR = 'amsec_verification_step';

	private const TTL = 300;

	private const TRIES = 5;

	public function park( int $user_id, string $redirect ): bool {
		if ( $user_id < 1 || headers_sent() || ! function_exists( 'set_transient' ) || ! function_exists( 'setcookie' ) ) {
			return false;
		}
		try {
			$token = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable ) {
			return false;
		}
		$stored = set_transient(
			$this->key( $token ),
			array(
				'user'     => $user_id,
				'tries'    => 0,
				'redirect' => $redirect,
			),
			self::TTL
		);
		if ( ! $stored ) {
			return false;
		}
		$cookie = setcookie(
			self::COOKIE,
			$token,
			array(
				'expires'  => time() + self::TTL,
				'path'     => '/',
				'secure'   => function_exists( 'is_ssl' ) && is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		if ( ! $cookie ) {
			delete_transient( $this->key( $token ) );
			return false;
		}
		$_COOKIE[ self::COOKIE ] = $token;
		return true;
	}

	public function redirect( string $username, \WP_Error $error ): void {
		unset( $username );
		if ( headers_sent() || ! in_array( self::ERROR, $error->get_error_codes(), true ) ) {
			return;
		}
		wp_safe_redirect( add_query_arg( 'action', 'amsec_verify', wp_login_url() ) );
		exit;
	}

	public function screen(): void {
		$record = $this->record();
		if ( null === $record ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		$error = new \WP_Error();
		if ( $this->posted() ) {
			$finished = $this->finish( $record );
			if ( $finished instanceof \WP_Error ) {
				$error = $finished;
			}
		}
		login_header( __( 'Verification', 'amazing-security' ), '', $error );
		echo '<p>' . esc_html__( 'Enter the code from the authenticator app you set up, or a recovery code.', 'amazing-security' ) . '</p>';
		echo '<form method="post" action="' . esc_url( add_query_arg( 'action', 'amsec_verify', wp_login_url() ) ) . '">';
		wp_nonce_field( 'amsec_login_step', 'amsec_login_step_nonce' );
		( new LoginFormFields() )->step();
		echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Continue', 'amazing-security' ) . '"></p></form>';
		login_footer();
		exit;
	}

	/**
	 * @param array{user: int, tries: int, redirect: string, token: string} $record
	 */
	private function finish( array $record ): ?\WP_Error {
		$nonce = isset( $_POST['amsec_login_step_nonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['amsec_login_step_nonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified on the next line for this logged-out code screen.
		if ( ! wp_verify_nonce( $nonce, 'amsec_login_step' ) ) {
			return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed. Start the sign-in again.', 'amazing-security' ) );
		}
		$factor = isset( $_POST['amsec_otp'] ) && is_string( $_POST['amsec_otp'] ) ? sanitize_text_field( wp_unslash( $_POST['amsec_otp'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce checked above.
		$totp   = new TotpAuthentication( new WordPressTotpStore( $GLOBALS['wpdb'] ), new SecretCipher( wp_salt( 'auth' ) ), new Totp() );
		if ( $totp->verifyFactor( $record['user'], $factor, time() ) ) {
			$this->clear( $record['token'] );
			$user = get_userdata( $record['user'] );
			if ( ! $user instanceof \WP_User ) {
				return new \WP_Error( 'amsec_verification_failed', __( 'Verification could not be completed.', 'amazing-security' ) );
			}
			wp_set_current_user( $user->ID );
			wp_set_auth_cookie( $user->ID, false );
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core sign-in hook, fired the same way as wp_signon().
			$redirect = '' !== $record['redirect'] ? $record['redirect'] : admin_url();
			wp_safe_redirect( apply_filters( 'login_redirect', $redirect, $redirect, $user ) ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core redirect hook, fired the same way as wp_signon().
			exit;
		}
		$tries = $record['tries'] + 1;
		if ( $tries >= self::TRIES ) {
			$this->clear( $record['token'] );
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		set_transient(
			$this->key( $record['token'] ),
			array(
				'user'     => $record['user'],
				'tries'    => $tries,
				'redirect' => $record['redirect'],
			),
			self::TTL
		);
		return new \WP_Error( 'amsec_verification_failed', __( 'That code did not match. Try again.', 'amazing-security' ) );
	}

	/**
	 * @return array{user: int, tries: int, redirect: string, token: string}|null
	 */
	private function record(): ?array {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( (string) $_COOKIE[ self::COOKIE ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The cookie only opens a short-lived code screen. It is not an auth session.
		if ( 1 !== preg_match( '/^[a-f0-9]{32}$/D', $token ) ) {
			return null;
		}
		$value = get_transient( $this->key( $token ) );
		if ( ! is_array( $value ) || ! isset( $value['user'], $value['tries'] ) || ! is_int( $value['user'] ) || ! is_int( $value['tries'] ) ) {
			return null;
		}
		$redirect = isset( $value['redirect'] ) && is_string( $value['redirect'] ) ? $value['redirect'] : '';
		return array(
			'user'     => $value['user'],
			'tries'    => $value['tries'],
			'redirect' => $redirect,
			'token'    => $token,
		);
	}

	private function posted(): bool {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		return 'post' === $method;
	}

	private function clear( string $token ): void {
		delete_transient( $this->key( $token ) );
		setcookie(
			self::COOKIE,
			'',
			array(
				'expires'  => time() - HOUR_IN_SECONDS,
				'path'     => '/',
				'secure'   => function_exists( 'is_ssl' ) && is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		unset( $_COOKIE[ self::COOKIE ] );
	}

	private function key( string $token ): string {
		return 'amsec_ls_' . hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
	}
}
