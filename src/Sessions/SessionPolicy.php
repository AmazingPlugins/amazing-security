<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Sessions;

final class SessionPolicy {
	public static function matchingTokens( string $adminToken, string $loginToken ): bool {
		return '' !== $adminToken && hash_equals( $adminToken, $loginToken );
	}

	public static function allowed( bool $post, bool $administrator, bool $editable, bool $cookie, bool $secure, bool $confirmed ): bool {
		return $post && $administrator && $editable && $cookie && $secure && $confirmed;
	}

	public static function safeRows( array $sessions ): array {
		$rows = array();
		foreach ( array_slice( $sessions, 0, 50 ) as $session ) {
			if ( is_array( $session ) && isset( $session['login'], $session['expiration'] ) ) {
				$rows[] = array(
					'login'      => max( 0, (int) $session['login'] ),
					'expiration' => max( 0, (int) $session['expiration'] ),
				);
			}
		}
		return $rows;
	}
}
