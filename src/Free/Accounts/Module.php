<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Login\BreachedPasswords;

/** Wires account protections. Each one stays off until an administrator turns it on. */
final class Module {
	public static function boot(): void {
		add_action( 'wp_loaded', array( self::class, 'idle' ) );
		add_action( 'user_register', array( self::class, 'markPending' ), 10, 1 );
		add_filter( 'wp_authenticate_user', array( self::class, 'beforePassword' ), 10, 2 );
		add_filter( 'authenticate', array( self::class, 'afterPassword' ), 27, 3 );
		add_filter( 'authenticate', array( self::class, 'blockPendingSession' ), 40, 3 );
		add_action( 'login_init', array( self::class, 'prepareChallenge' ) );
		add_action( 'template_redirect', array( self::class, 'prepareChallenge' ) );
		add_action( 'login_form', array( self::class, 'loginFields' ) );
		add_action( 'woocommerce_login_form', array( self::class, 'loginFields' ) );
		add_action( 'admin_menu', array( AccountPage::class, 'menu' ) );
		add_action( 'admin_post_amsec_accounts_save', array( AccountPage::class, 'save' ) );
		add_action( 'admin_post_amsec_accounts_approve', array( AccountPage::class, 'approve' ) );
	}

	public static function idle(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$user_id = get_current_user_id();
		if ( $user_id < 1 ) {
			return;
		}
		$minutes  = IdleLogout::minutes( self::option( IdleLogout::OPTION ) );
		$seen     = IdleLogout::seen( get_user_meta( $user_id, IdleLogout::META, true ) );
		$now      = time();
		$decision = IdleLogout::decision( $minutes, $seen, $now );
		if ( 'off' === $decision ) {
			return;
		}
		if ( 'logout' === $decision ) {
			self::endSession( $user_id );
		}
		update_user_meta( $user_id, IdleLogout::META, (string) $now );
	}

	public static function markPending( int $user_id ): void {
		$manager = current_user_can( 'create_users' ) || ( defined( 'WP_CLI' ) && WP_CLI );
		if ( $user_id < 1 || ! RegistrationApproval::marks( RegistrationApproval::enabled( self::option( RegistrationApproval::OPTION ) ), $manager ) ) {
			return;
		}
		update_user_meta( $user_id, RegistrationApproval::META, '1' );
	}

	public static function beforePassword( mixed $user, string $password ): mixed {
		unset( $password );
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		if ( 'reject' === self::challengeDecision() ) {
			return new \WP_Error( 'amsec_login_challenge', __( 'Enter the sum of the two numbers and leave the extra field blank.', 'amazing-security' ) );
		}
		return self::pendingError( $user );
	}

	public static function afterPassword( mixed $user, string $username, string $password ): mixed {
		unset( $username );
		$user = self::breach( $user, $password );
		$user = self::pendingError( $user );
		return self::emailFactor( $user, $password );
	}

	public static function blockPendingSession( mixed $user, string $username, string $password ): mixed {
		unset( $username, $password );
		return self::pendingError( $user );
	}

	public static function loginFields(): void {
		if ( '1' === self::option( EmailFactor::OPTION ) ) {
			echo '<p class="amsec-email-factor"><label for="amsec-email-code">' . esc_html__( 'Email code', 'amazing-security' ) . '</label> ';
			echo '<input class="input" type="text" id="amsec-email-code" name="amsec_email_code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" value=""></p>';
		}
		self::renderChallenge();
	}

	private static function endSession( int $user_id ): void {
		$token = wp_get_session_token();
		if ( '' !== $token ) {
			\WP_Session_Tokens::get_instance( $user_id )->destroy( $token );
		}
		wp_logout();
	}

	private static function breach( mixed $user, string $password ): mixed {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		$decision = AdminBreachBlock::decision(
			self::option( 'amsec_common_passwords' ),
			self::isAdministrator( $user ),
			$password,
			static function ( string $candidate ): bool {
				return BreachedPasswords::listed( $candidate );
			}
		);
		if ( 'block' === $decision ) {
			return new \WP_Error( 'amsec_breached_password', __( 'This administrator password matched a breach list. The password itself was not sent.', 'amazing-security' ) );
		}
		return $user;
	}

	private static function pendingError( mixed $user ): mixed {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		$meta = get_user_meta( $user->ID, RegistrationApproval::META, true );
		if ( ! RegistrationApproval::blocks( RegistrationApproval::enabled( self::option( RegistrationApproval::OPTION ) ), $meta ) ) {
			return $user;
		}
		return new \WP_Error( 'amsec_registration_pending', __( 'An administrator still needs to approve this account.', 'amazing-security' ) );
	}

	private static function emailFactor( mixed $user, string $password ): mixed {
		if ( ! $user instanceof \WP_User ) {
			return $user;
		}
		$stored = EmailFactor::unpack( get_user_meta( $user->ID, EmailFactor::META, true ) );
		if ( null !== $stored && '' !== self::posted( 'amsec_email_code' ) ) {
			$stored['tries'] = self::reserveEmailTry( $user->ID ) ? 0 : EmailFactor::TRIES;
		}
		$decision = EmailFactor::decision(
			RegistrationApproval::enabled( self::option( EmailFactor::OPTION ) ),
			EmailFactor::enrolled(
				get_user_meta( $user->ID, 'amsec_totp_seed', true ),
				get_user_meta( $user->ID, 'amsec_totp_v1', true )
			),
			self::apiRequest(),
			$password,
			true,
			self::posted( 'amsec_email_code' ),
			$stored,
			time(),
			wp_salt( 'auth' )
		);
		if ( 'accept' === $decision ) {
			delete_user_meta( $user->ID, EmailFactor::META );
			return $user;
		}
		if ( 'skip' === $decision ) {
			return $user;
		}
		if ( 'send' === $decision ) {
			return self::sendEmailCode( $user );
		}
		return new \WP_Error( 'amsec_email_factor', __( 'Enter the email code and sign in again.', 'amazing-security' ) );
	}

	/** Atomically spends one of the current code's tries, so parallel guesses can't exceed EmailFactor::TRIES. */
	private static function reserveEmailTry( int $user_id ): bool {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- A single conditional UPDATE is the atomic counter; the meta cache is cleared below.
		$reserved = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->usermeta} SET meta_value = CAST(meta_value AS UNSIGNED) + 1 WHERE user_id = %d AND meta_key = %s AND CAST(meta_value AS UNSIGNED) < %d", $user_id, EmailFactor::TRIES_META, EmailFactor::TRIES ) );
		wp_cache_delete( $user_id, 'user_meta' );
		return 1 === $reserved;
	}

	private static function sendEmailCode( \WP_User $user ): \WP_Error {
		$failed = new \WP_Error( 'amsec_email_factor', __( 'The email code could not be sent. Try again.', 'amazing-security' ) );
		$email  = $user->user_email;
		if ( ! is_string( $email ) || ! is_email( $email ) ) {
			return $failed;
		}
		$code = EmailFactor::code();
		$sent = wp_mail(
			$email,
			__( 'Sign-in code', 'amazing-security' ),
			sprintf(
				/* translators: %s: six digit sign-in code */
				__( 'Your sign-in code is %s. It expires in 10 minutes. If you did not try to sign in, ignore this email.', 'amazing-security' ),
				$code
			)
		);
		if ( true !== $sent ) {
			return $failed;
		}
		$json = wp_json_encode( EmailFactor::record( $code, time(), wp_salt( 'auth' ) ) );
		if ( ! is_string( $json ) || false === update_user_meta( $user->ID, EmailFactor::META, $json ) ) {
			return $failed;
		}
		update_user_meta( $user->ID, EmailFactor::TRIES_META, '0' );
		return new \WP_Error( 'amsec_email_factor', __( 'Enter the email code and sign in again.', 'amazing-security' ) );
	}

	private static function challengeDecision(): string {
		if ( '1' !== self::option( LoginChallenge::OPTION ) ) {
			return 'allow';
		}
		$token    = self::challengeToken();
		$expected = self::expectedSum( $token );
		if ( '' !== $token ) {
			// One answer per question: a retry must load the new pair that login_init just issued.
			delete_transient( LoginChallenge::transientKey( $token ) );
		}
		return LoginChallenge::decision(
			true,
			defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
			self::apiRequest(),
			$token,
			$expected,
			self::posted( LoginChallenge::SUM ),
			self::posted( LoginChallenge::HONEYPOT )
		);
	}

	/** @var array{left: int, right: int}|null */
	private static ?array $challengePair = null;

	public static function prepareChallenge(): void {
		if ( null !== self::$challengePair || headers_sent() || is_user_logged_in() ) {
			return;
		}
		if ( '1' !== self::option( LoginChallenge::OPTION ) ) {
			return;
		}
		$on_login   = 'wp-login.php' === ( $GLOBALS['pagenow'] ?? '' );
		$on_account = function_exists( 'is_account_page' ) && is_account_page();
		if ( ! $on_login && ! $on_account ) {
			return;
		}
		$pair = LoginChallenge::pair( wp_rand( 2, 9 ), wp_rand( 2, 9 ) );
		if ( null === $pair ) {
			return;
		}
		try {
			$token = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $exception ) {
			unset( $exception );
			return;
		}
		$cookie = setcookie(
			LoginChallenge::COOKIE,
			$token,
			array(
				'expires'  => time() + EmailFactor::TTL,
				'path'     => '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		if ( ! $cookie ) {
			return;
		}
		set_transient( LoginChallenge::transientKey( $token ), (string) $pair['sum'], EmailFactor::TTL );
		self::$challengePair = array(
			'left'  => $pair['left'],
			'right' => $pair['right'],
		);
	}

	private static function renderChallenge(): void {
		if ( null === self::$challengePair ) {
			return;
		}
		$question = sprintf(
			/* translators: 1: first number, 2: second number */
			__( 'What is %1$d + %2$d?', 'amazing-security' ),
			self::$challengePair['left'],
			self::$challengePair['right']
		);
		echo '<p class="amsec-login-challenge"><label for="amsec-login-sum">' . esc_html( $question ) . '</label> ';
		echo '<input class="input" type="text" id="amsec-login-sum" name="' . esc_attr( LoginChallenge::SUM ) . '" inputmode="numeric" autocomplete="off" size="4" value=""></p>';
		echo '<p style="position:absolute;left:-9999px" aria-hidden="true"><label>' . esc_html__( 'Company', 'amazing-security' ) . ' <input type="text" name="' . esc_attr( LoginChallenge::HONEYPOT ) . '" value="" tabindex="-1" autocomplete="off"></label></p>';
	}

	private static function challengeToken(): string {
		// Login cookies are not a plugin admin nonce. The token is kept only when it is 32 hex characters.
		$raw = isset( $_COOKIE[ LoginChallenge::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ LoginChallenge::COOKIE ] ) ) : '';
		if ( ! is_string( $raw ) ) {
			return '';
		}
		$raw = wp_unslash( $raw );
		return LoginChallenge::validToken( $raw ) ? $raw : '';
	}

	private static function expectedSum( string $token ): ?string {
		if ( ! LoginChallenge::validToken( $token ) ) {
			return null;
		}
		$value = get_transient( LoginChallenge::transientKey( $token ) );
		if ( is_int( $value ) ) {
			$value = (string) $value;
		}
		if ( ! is_string( $value ) || 1 !== preg_match( '/\A\d{1,2}\z/', $value ) ) {
			return null;
		}
		return $value;
	}

	private static function posted( string $key ): string {
		// Login fields are checked by WordPress, not a plugin admin nonce. The value is not sanitized because it can be a password.
		$value = isset( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = wp_unslash( $value );
		return strlen( $value ) > 64 ? '' : $value;
	}

	private static function isAdministrator( \WP_User $user ): bool {
		$roles = $user->roles ?? array();
		return is_array( $roles ) && in_array( 'administrator', $roles, true );
	}

	private static function apiRequest(): bool {
		return ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST );
	}

	private static function option( string $key ): string {
		$value = get_option( $key, '0' );
		if ( is_int( $value ) ) {
			$value = (string) $value;
		}
		return is_string( $value ) ? $value : '0';
	}
}
