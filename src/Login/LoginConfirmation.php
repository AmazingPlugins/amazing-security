<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Local WordPress login confirmation. It does not call a CAPTCHA service. */
final class LoginConfirmation {
	private readonly Closure $enabled;

	public function __construct( callable $enabled ) {
		$this->enabled = Closure::fromCallable( $enabled );
	}

	public static function decision( bool $enabled, array $post, bool $xmlRpc, bool $application ): string {
		if ( ! $enabled || $xmlRpc || $application || ! isset( $post['log'], $post['pwd'] ) || ! is_string( $post['pwd'] ) || '' === $post['pwd'] ) {
			return 'allow';
		}
		$trap = $post['amsec_login_website'] ?? '';
		$box  = $post['amsec_login_confirm'] ?? '';
		if ( ! is_string( $trap ) || '' !== $trap || '1' !== $box ) {
			return 'reject';
		}
		return 'allow';
	}

	public function render(): void {
		if ( ! $this->isEnabled() ) {
			return;
		}
		echo '<p class="amsec-login-confirm"><label><input type="checkbox" name="amsec_login_confirm" value="1"> ' . esc_html__( 'Confirm this sign-in', 'amazing-security' ) . '</label></p>';
		echo '<p style="position:absolute;left:-9999px" aria-hidden="true"><label>' . esc_html__( 'Website', 'amazing-security' ) . ' <input type="text" name="amsec_login_website" value="" tabindex="-1" autocomplete="off"></label></p>';
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		unset( $username, $password );
		if ( $user instanceof \WP_User && 'reject' === self::decision( $this->isEnabled(), $this->posted(), defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST, ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) ) {
			return new \WP_Error( 'amsec_login_confirm', __( 'Confirm this sign-in and try again.', 'amazing-security' ) );
		}
		return $user;
	}

	private function posted(): array {
		$keys = array( 'log', 'pwd', 'amsec_login_website', 'amsec_login_confirm' );
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
