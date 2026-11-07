<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use Closure;
use AmazingPlugins\Security\Request\PostedPassword;

/** Rejects a new password on the local list or a breach-list prefix. It does not block an existing sign-in. */
final class CommonPasswordHooks {
	private readonly Closure $enabled;
	private readonly Closure $breached;

	public function __construct( callable $enabled, ?callable $breached = null ) {
		$this->enabled  = Closure::fromCallable( $enabled );
		$this->breached = Closure::fromCallable( $breached ?? array( BreachedPasswords::class, 'listed' ) );
	}

	// WordPress passes a stdClass here, not a WP_User (see edit_user()).
	public function profile( \WP_Error $errors, bool $update, object $user ): void {
		unset( $update, $user );
		$this->rejectPosted( $errors, 'pass1' );
	}

	public function registration( \WP_Error $errors, string $login, string $email ): \WP_Error {
		unset( $login, $email );
		$this->rejectPosted( $errors, 'user_pass' );
		return $errors;
	}

	public function reset( \WP_Error $errors, \WP_User $user ): void {
		unset( $user );
		$this->rejectPosted( $errors, 'pass1' );
	}

	private function reject( \WP_Error $errors, string $password ): void {
		if ( ! $this->isEnabled() || '' === $password ) {
			return;
		}
		if ( CommonPasswords::matches( $password ) ) {
			$errors->add( 'ironlatch_common_password', __( 'Choose a password that is not on the local common-password list.', 'ironlatch-security-scanner' ) );
			return;
		}
		try {
			$listed = ( $this->breached )( $password );
		} catch ( \Throwable ) {
			return;
		}
		if ( true === $listed ) {
			$errors->add( 'ironlatch_breached_password', __( 'Choose a different password. A breach list matched a hash prefix, and the password itself was not sent.', 'ironlatch-security-scanner' ) );
		}
	}

	private function rejectPosted( \WP_Error $errors, string $key ): void {
		if ( $this->isEnabled() && PostedPassword::rejected( $key, 4096 ) ) {
			$errors->add( 'ironlatch_invalid_password', __( 'Choose a different password without control characters.', 'ironlatch-security-scanner' ) );
			return;
		}
		$this->reject( $errors, PostedPassword::read( $key, 4096 ) ?? '' );
	}

	private function isEnabled(): bool {
		return (bool) ( $this->enabled )();
	}
}
