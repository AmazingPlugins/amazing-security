<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use Closure;

/** One WordPress login message. It does not send login attempts anywhere. */
final class LoginHints {
	private readonly Closure $enabled;

	public function __construct( callable $enabled ) {
		$this->enabled = Closure::fromCallable( $enabled );
	}

	public static function generic( bool $enabled, array $messages ): array {
		if ( ! $enabled ) {
			return $messages;
		}
		$changed = false;
		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			if ( array_key_exists( $code, $messages ) ) {
				unset( $messages[ $code ] );
				$changed = true;
			}
		}
		if ( $changed ) {
			$messages['amsec_generic_login'] = __( 'The username or password is incorrect.', 'amazing-security-scanner' );
		}
		return $messages;
	}

	public function errors( mixed $errors ): mixed {
		if ( ! $errors instanceof \WP_Error ) {
			return $errors;
		}
		$messages = array();
		foreach ( array( 'invalid_username', 'invalid_email', 'incorrect_password' ) as $code ) {
			$message = $errors->get_error_message( $code );
			if ( is_string( $message ) && '' !== $message ) {
				$messages[ $code ] = $message;
			}
		}
		$next = self::generic( ( $this->enabled )(), $messages );
		if ( $next === $messages ) {
			return $errors;
		}
		foreach ( array_keys( $messages ) as $code ) {
			if ( ! array_key_exists( $code, $next ) ) {
				$errors->remove( $code );
			}
		}
		if ( isset( $next['amsec_generic_login'] ) ) {
			$errors->add( 'amsec_generic_login', $next['amsec_generic_login'] );
		}
		return $errors;
	}
}
