<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\PasswordRules;

defined( 'ABSPATH' ) || exit;

/** Boots the password-rule screen and rejects a new or reset password that fails an enabled rule. */
final class Module {
	public static function boot(): void {
		$page = new Page();
		add_action( 'admin_menu', array( $page, 'register' ) );
		add_action( 'admin_post_amsec_password_rules', array( $page, 'save' ) );
		add_action( 'validate_password_reset', array( self::class, 'reset' ), 10, 2 );
		add_action( 'user_profile_update_errors', array( self::class, 'profile' ), 10, 3 );
		add_filter( 'rest_request_before_callbacks', array( self::class, 'rest' ), 10, 3 );
		add_filter( 'woocommerce_registration_errors', array( self::class, 'registration' ), 10, 3 );
		add_action( 'woocommerce_save_account_details_errors', array( self::class, 'account' ), 10, 2 );
		add_action( 'woocommerce_after_checkout_validation', array( self::class, 'checkout' ), 10, 2 );
	}

	public static function stored(): string {
		$value = get_option( Decision::OPTION, '0' );
		if ( is_int( $value ) ) {
			$value = (string) $value;
		}
		if ( ! is_string( $value ) ) {
			return '0';
		}
		return Decision::normalize( $value );
	}

	public static function reset( \WP_Error $errors, mixed $user ): void {
		$password = self::postedPassword( 'pass1' );
		if ( null === $password || '' === $password ) {
			return;
		}
		self::addError( $errors, $password, 'reset', self::loginOf( $user ), self::emailOf( $user ), self::idOf( $user ) );
		unset( $password );
	}

	public static function profile( \WP_Error $errors, bool $update, object $user ): void {
		$password = self::postedPassword( 'pass1' );
		if ( null === $password || ( $update && '' === $password ) ) {
			return;
		}
		self::addError( $errors, $password, 'new', self::loginOf( $user ), self::emailOf( $user ), self::idOf( $user ) );
		unset( $password );
	}

	public static function registration( mixed $errors, string $username, string $email ): mixed {
		if ( $errors instanceof \WP_Error ) {
			self::rejectPosted( $errors, array( 'password', 'account_password', 'user_pass', 'pass1' ), 'new', $username, $email, 0 );
		}
		return $errors;
	}

	public static function account( \WP_Error $errors, mixed $user ): void {
		$password = self::postedPassword( 'password_1' );
		if ( null === $password || '' === $password ) {
			return;
		}
		self::addError( $errors, $password, 'new', self::loginOf( $user ), self::emailOf( $user ), self::idOf( $user ) );
		unset( $password );
	}

	/**
	 * @param array<mixed> $data
	 */
	public static function checkout( array $data, \WP_Error $errors ): void {
		$password = $data['account_password'] ?? null;
		if ( ! is_string( $password ) || '' === trim( $password ) ) {
			return;
		}
		$username = isset( $data['account_username'] ) && is_string( $data['account_username'] ) ? $data['account_username'] : '';
		$email    = isset( $data['billing_email'] ) && is_string( $data['billing_email'] ) ? $data['billing_email'] : '';
		self::addError( $errors, trim( $password ), 'new', $username, $email, 0 );
		unset( $password );
	}

	public static function rest( mixed $response, array $handler, \WP_REST_Request $request ): mixed {
		unset( $handler );
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$route = $request->get_route();
		if ( ! is_string( $route ) || ! str_starts_with( $route, '/wp/v2/users' ) ) {
			return $response;
		}
		$rest = substr( $route, strlen( '/wp/v2/users' ) );
		if ( '' !== $rest && 1 !== preg_match( '#^/[0-9]+$#', $rest ) ) {
			return $response;
		}
		if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH' ), true ) ) {
			return $response;
		}
		if ( ! $request->has_param( 'password' ) ) {
			return $response;
		}
		$password = $request->get_param( 'password' );
		if ( ! is_string( $password ) || '' === $password ) {
			return $response;
		}
		$username = $request->get_param( 'username' );
		$email    = $request->get_param( 'email' );
		$user_id  = 0;
		if ( 1 === preg_match( '#^/([0-9]+)$#', $rest, $match ) ) {
			$user_id = (int) $match[1];
		}
		$code = self::codeFor( trim( $password ), 'new', is_string( $username ) ? $username : '', is_string( $email ) ? $email : '', $user_id );
		unset( $password );
		if ( null === $code ) {
			return $response;
		}
		return new \WP_Error( 'amsec_password_' . $code, self::message( $code ), array( 'status' => 400 ) );
	}

	private static function addError( \WP_Error $errors, string $password, string $when, string $username, string $email, int $user_id ): void {
		$code = self::codeFor( $password, $when, $username, $email, $user_id );
		unset( $password );
		if ( null === $code ) {
			return;
		}
		$errors->add( 'amsec_password_' . $code, self::message( $code ) );
	}

	private static function codeFor( string $password, string $when, string $username, string $email, int $user_id ): ?string {
		$rules                  = self::rules();
		list($username, $email) = self::accountName( $user_id, $username, $email );
		$code                   = Decision::violation(
			$when,
			$password,
			$rules['min'],
			$rules['number'],
			$rules['mixed'],
			$rules['symbol'],
			$rules['name'],
			$rules['reuse'],
			$username,
			$email,
			self::matchesCurrent( $password, $user_id, $rules['reuse'] )
		);
		unset( $password );
		return $code;
	}

	/**
	 * @return array{min: string, number: string, mixed: string, symbol: string, name: string, reuse: string}
	 */
	private static function rules(): array {
		return array(
			'min'    => self::stored(),
			'number' => self::flag( Decision::NUMBER ),
			'mixed'  => self::flag( Decision::MIXED ),
			'symbol' => self::flag( Decision::SYMBOL ),
			'name'   => self::flag( Decision::NAME ),
			'reuse'  => self::flag( Decision::REUSE ),
		);
	}

	private static function flag( string $option ): string {
		$value = get_option( $option, '0' );
		return Decision::enabled( is_scalar( $value ) ? (string) $value : '0' ) ? '1' : '0';
	}

	private static function matchesCurrent( string $password, int $user_id, string $reuse ): bool {
		if ( ! Decision::enabled( $reuse ) || $user_id < 1 || ! function_exists( 'wp_check_password' ) || ! function_exists( 'get_userdata' ) ) {
			return false;
		}
		$stored = get_userdata( $user_id );
		if ( ! $stored instanceof \WP_User || ! is_string( $stored->user_pass ) || '' === $stored->user_pass ) {
			return false;
		}
		$hash  = $stored->user_pass;
		$match = wp_check_password( $password, $hash, $user_id );
		unset( $password, $hash );
		return true === $match;
	}

	private static function message( string $code ): string {
		if ( 'length' === $code ) {
			return sprintf(
				/* translators: %d: minimum number of characters. */
				__( 'Use at least %d characters.', 'amazing-security' ),
				Decision::minimum( self::stored() )
			);
		}
		if ( 'number' === $code ) {
			return __( 'Include a number.', 'amazing-security' );
		}
		if ( 'mixed' === $code ) {
			return __( 'Include an uppercase letter and a lowercase letter.', 'amazing-security' );
		}
		if ( 'symbol' === $code ) {
			return __( 'Include a symbol.', 'amazing-security' );
		}
		if ( 'name' === $code ) {
			return __( 'Do not include the account name or the email name.', 'amazing-security' );
		}
		if ( 'reuse' === $code ) {
			return __( 'Choose a password that is different from the current one.', 'amazing-security' );
		}
		return __( 'Choose a different password.', 'amazing-security' );
	}

	/**
	 * @param array<int, string> $keys
	 */
	private static function rejectPosted( \WP_Error $errors, array $keys, string $when, string $username, string $email, int $user_id ): void {
		foreach ( $keys as $key ) {
			$password = self::postedPassword( $key );
			if ( null === $password || '' === $password ) {
				continue;
			}
			self::addError( $errors, $password, $when, $username, $email, $user_id );
			unset( $password );
			return;
		}
	}

	private static function postedPassword( string $key ): ?string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The profile, reset, or checkout form nonce is already checked.
		if ( ! isset( $_POST[ $key ] ) || ! is_string( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The password is measured, then dropped.
			return null;
		}
		$value = wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The password is measured, then dropped.
		if ( ! is_string( $value ) ) {
			return null;
		}
		return trim( $value );
	}

	/**
	 * @return array{0: string, 1: string}
	 */
	private static function accountName( int $user_id, string $username, string $email ): array {
		if ( ( '' !== $username && '' !== $email ) || $user_id < 1 || ! function_exists( 'get_userdata' ) ) {
			return array( $username, $email );
		}
		$stored = get_userdata( $user_id );
		if ( ! $stored instanceof \WP_User ) {
			return array( $username, $email );
		}
		if ( '' === $username ) {
			$username = $stored->user_login;
		}
		if ( '' === $email ) {
			$email = $stored->user_email;
		}
		return array( $username, $email );
	}

	private static function loginOf( mixed $user ): string {
		return is_object( $user ) && isset( $user->user_login ) && is_string( $user->user_login ) ? $user->user_login : '';
	}

	private static function emailOf( mixed $user ): string {
		return is_object( $user ) && isset( $user->user_email ) && is_string( $user->user_email ) ? $user->user_email : '';
	}

	private static function idOf( mixed $user ): int {
		return is_object( $user ) && isset( $user->ID ) ? (int) $user->ID : 0;
	}
}
