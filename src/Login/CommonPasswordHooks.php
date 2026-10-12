<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

use Closure;

/** Rejects a new password on the local list or a breach-list prefix. It does not block an existing sign-in. */
final class CommonPasswordHooks {
	private readonly Closure $enabled;
	private readonly Closure $breached;

	public function __construct( callable $enabled, ?callable $breached = null ) {
		$this->enabled  = Closure::fromCallable( $enabled );
		$this->breached = Closure::fromCallable( $breached ?? array( BreachedPasswords::class, 'listed' ) );
	}

	/** WordPress passes a plain object here when it saves a profile, so the user argument is not typed as WP_User. */
	public function profile( \WP_Error $errors, bool $update, object $user ): void {
		unset( $update, $user );
		$this->reject( $errors, $this->posted( 'pass1' ) );
	}

	public function registration( \WP_Error $errors, string $login, string $email ): \WP_Error {
		unset( $login, $email );
		$this->reject( $errors, $this->posted( 'user_pass' ) );
		return $errors;
	}

	public function reset( \WP_Error $errors, \WP_User $user ): void {
		unset( $user );
		$this->reject( $errors, $this->posted( 'pass1' ) );
	}

	private function reject( \WP_Error $errors, string $password ): void {
		if ( ! $this->isEnabled() || '' === $password ) {
			return;
		}
		if ( CommonPasswords::matches( $password ) ) {
			$errors->add( 'amsec_common_password', __( 'Choose a password that is not on the local common-password list.', 'amazing-security' ) );
			return;
		}
		try {
			$listed = ( $this->breached )( $password );
		} catch ( \Throwable ) {
			return;
		}
		if ( true === $listed ) {
			$errors->add( 'amsec_breached_password', __( 'Choose a different password. A breach list matched a hash prefix, and the password itself was not sent.', 'amazing-security' ) );
		}
	}

	private function posted( string $key ): string {
		// Password bytes stay exact. The profile, registration, or reset form already checked its nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$value = $_POST[ $key ] ?? '';
		return is_string( $value ) ? wp_unslash( $value ) : '';
	}

	private function isEnabled(): bool {
		return (bool) ( $this->enabled )();
	}
}
