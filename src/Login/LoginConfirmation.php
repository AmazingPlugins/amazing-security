<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Hidden bot trap on the WordPress login form. Nothing to tick, and no outside CAPTCHA service. */
final class LoginConfirmation {
	public const FIELD = 'amsec_lt_note';

	private readonly Closure $enabled;

	public function __construct( callable $enabled ) {
		$this->enabled = Closure::fromCallable( $enabled );
	}

	/** Only a filled hidden field is refused. A missing field (another login form) is allowed. */
	public static function decision( bool $enabled, array $post, bool $xmlRpc, bool $application ): string {
		if ( ! $enabled || $xmlRpc || $application || ! isset( $post['log'], $post['pwd'] ) || ! is_string( $post['pwd'] ) || '' === $post['pwd'] ) {
			return 'allow';
		}
		$trap = $post[ self::FIELD ] ?? '';
		return is_string( $trap ) && '' === $trap ? 'allow' : 'reject';
	}

	/** A field people never see. Bots that fill every input give themselves away; nobody has to tick anything. */
	public function render(): void {
		if ( ! $this->isEnabled() ) {
			return;
		}
		// The name avoids words browsers autofill (website, url, email), so a real person's sign-in is never caught.
		echo '<p class="amsec-login-trap" style="position:absolute;left:-9999px" aria-hidden="true"><label>' . esc_html__( 'Leave this empty', 'amazing-security' ) . ' <input type="text" name="' . esc_attr( self::FIELD ) . '" value="" tabindex="-1" autocomplete="off"></label></p>';
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		unset( $username, $password );
		if ( $user instanceof \WP_User && 'reject' === self::decision( $this->isEnabled(), $this->posted(), defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST, ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) ) {
			return new \WP_Error( 'amsec_login_confirm', __( 'This sign-in could not be completed. Reload the page and try again.', 'amazing-security' ) );
		}
		return $user;
	}

	private function posted(): array {
		$keys = array( 'log', 'pwd', self::FIELD );
		$post = array();
		foreach ( $keys as $key ) {
			// Login fields stay exact. WordPress checks this form, not a plugin admin nonce.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$value = $_POST[ $key ] ?? null;
			if ( is_string( $value ) ) {
				$post[ $key ] = wp_unslash( $value );
			}
		}
		return $post;
	}

	private function isEnabled(): bool {
		return (bool) ( $this->enabled )();
	}
}
