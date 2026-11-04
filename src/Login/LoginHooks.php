<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

final class LoginHooks {
	public function __construct( private RateLimiter $limiter, private AddressKey $addresses ) {}

	public static function isInteractiveRequest( array $server, array $post, bool $xmlRpc, bool $applicationRequest ): bool {
		if ( $xmlRpc || $applicationRequest || 'POST' !== ( $server['REQUEST_METHOD'] ?? null ) ) {
			return false;
		}
		return ( isset( $post['log'], $post['pwd'] ) || isset( $post['username'], $post['password'] ) );
	}

	public function authenticate( mixed $user, string $username, string $password ): mixed {
		if ( '' === $username || '' === $password || ! $this->interactive() ) {
			return $user;
		}
		$decision = $this->limiter->beforePassword( $this->addresses->fromServer( \AmazingPlugins\Security\Proxy\WordPressClientAddress::request() ), time() );
		if ( $decision->blocked ) {
			return new \WP_Error( 'ironlatch_rate_limited', __( 'Please try again shortly.', 'ironlatch-security-scanner' ) );
		}
		return $user;
	}

	public function failed( string $username, \WP_Error $error ): void {
		// WordPress requires the username argument; never retain it in rate-limit storage.
		// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$ignored = array( 'ironlatch_rate_limited', 'ironlatch_login_confirm', 'ironlatch_login_challenge', 'ironlatch_email_factor', 'ironlatch_registration_pending' );
		if ( ! $this->interactive() || array_intersect( $ignored, $error->get_error_codes() ) ) {
			return;
		}
		$this->limiter->afterFailure( $this->addresses->fromServer( \AmazingPlugins\Security\Proxy\WordPressClientAddress::request() ), time() );
	}

	private function interactive(): bool {
		$xmlRpc = defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
		$app    = ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI );
		// Login POSTs are authenticated by WordPress; they have no plugin admin nonce. Only the keys the check reads are passed on.
		$server = array( 'REQUEST_METHOD' => isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' );
		$post   = array();
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Login form; only whether each field was sent is passed on, never its value.
		foreach ( array( 'log', 'pwd', 'username', 'password' ) as $field ) {
			if ( isset( $_POST[ $field ] ) ) {
				$post[ $field ] = true;
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		return self::isInteractiveRequest( $server, $post, $xmlRpc, $app );
	}
}
