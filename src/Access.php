<?php

declare(strict_types=1);

namespace AmazingPlugins\Security;

defined( 'ABSPATH' ) || exit;

/** Who may see or change an account. */
final class Access {
	/** Session list and detail. An administrator, or the account owner. */
	public static function session( bool $administrator, int $viewer, int $subject ): bool {
		return 0 < $subject && 0 < $viewer && ( $administrator || $viewer === $subject );
	}

	/** Passkeys and authenticator setup. The signed-in account only. */
	public static function ownSecret( int $viewer, int $subject ): bool {
		return 0 < $viewer && $viewer === $subject;
	}

	/** A reset or grace period for a different account. An administrator, and not their own account. */
	public static function otherAccount( bool $administrator, int $viewer, int $subject ): bool {
		return $administrator && 0 < $viewer && 0 < $subject && $viewer !== $subject;
	}
}
