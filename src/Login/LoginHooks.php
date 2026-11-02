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
		$decision = $this->limiter->beforePassword( $this->addresses->fromServer( $_SERVER ), time() );
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
		$this->limiter->afterFailure( $this->addresses->fromServer( $_SERVER ), time() );
	}

	private function interactive(): bool {
		$xmlRpc = defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
		$app    = ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI );
		// Login POSTs are authenticated by WordPress; they have no plugin admin nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return self::isInteractiveRequest( $_SERVER, $_POST, $xmlRpc, $app );
	}
}
