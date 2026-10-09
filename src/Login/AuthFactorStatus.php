<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Login;

/** Pure status for passkeys / TOTP owned by other plugins. */
final class AuthFactorStatus {
	public const ACTIVE    = 'active';
	public const AVAILABLE = 'available';
	public const MISSING   = 'missing';

	public static function resolve( bool $providerPresent, bool $inUse ): string {
		if ( ! $providerPresent ) {
			return self::MISSING;
		}
		return $inUse ? self::ACTIVE : self::AVAILABLE;
	}
}
