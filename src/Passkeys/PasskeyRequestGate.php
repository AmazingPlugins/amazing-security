<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Passkeys;

final class PasskeyRequestGate {
	public static function request( PasskeyContext $context, array $server, bool $https ): bool {
		return $https && 'POST' === ( $server['REQUEST_METHOD'] ?? null ) && $context->acceptOrigin( $server['HTTP_ORIGIN'] ?? null );
	}
	public static function own( int $currentId, int $cookieId, string $cookieToken, string $sessionToken, bool $canRead, bool $nonce ): bool {
		return $currentId > 0 && $currentId === $cookieId && '' !== $cookieToken && hash_equals( $cookieToken, $sessionToken ) && $canRead && $nonce;
	}
}
