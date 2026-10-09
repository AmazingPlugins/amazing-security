<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Accounts;

/** Administrator sign-in breach check. The listed callback is injected. */
final class AdminBreachBlock {
	/**
	 * Skip unless the existing common-password switch is the string 1, the account is an administrator, and the password is not empty.
	 *
	 * @param callable(string): bool $listed
	 */
	public static function decision( string $option, bool $isAdmin, string $password, callable $listed ): string {
		if ( '1' !== $option || ! $isAdmin || '' === $password ) {
			return 'skip';
		}
		return true === $listed( $password ) ? 'block' : 'allow';
	}
}
