<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

defined( 'ABSPATH' ) || exit;

use Closure;

/** Local account-name exposure gates. They do not send site data anywhere. */
final class AccountExposure {
	private readonly Closure $authors;
	private readonly Closure $users;

	public function __construct( callable $authors, callable $users ) {
		$this->authors = Closure::fromCallable( $authors );
		$this->users   = Closure::fromCallable( $users );
	}

	public static function authorDecision( bool $enabled, bool $loggedIn, string $author, string $authorName ): string {
		if ( ! $enabled || $loggedIn || ( '' === $author && '' === $authorName ) ) {
			return 'allow';
		}
		return 'redirect';
	}

	public static function restDecision( bool $enabled, bool $loggedIn, string $route, string $method ): string {
		if ( ! $enabled || $loggedIn || 'GET' !== strtoupper( $method ) ) {
			return 'allow';
		}
		return 1 === preg_match( '~^/wp/v2/users(?:/[0-9]+)?/?$~i', $route ) ? 'deny' : 'allow';
	}

	public function redirect(): void {
		$author = get_query_var( 'author' );
		$name   = get_query_var( 'author_name' );
		if ( 'redirect' !== self::authorDecision( ( $this->authors )(), is_user_logged_in(), is_scalar( $author ) ? (string) $author : '', is_string( $name ) ? $name : '' ) ) {
			return;
		}
		wp_safe_redirect( home_url( '/' ) );
		exit;
	}

	public function rest( mixed $result, mixed $server, mixed $request ): mixed {
		if ( null !== $result || ! $server instanceof \WP_REST_Server || ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		if ( 'deny' !== self::restDecision( ( $this->users )(), is_user_logged_in(), $request->get_route(), $request->get_method() ) ) {
			return $result;
		}
		return new \WP_Error(
			'amsec_rest_users',
			__( 'You must be logged in to list accounts.', 'amazingplugins-security-scanner' ),
			array( 'status' => 401 )
		);
	}
}
