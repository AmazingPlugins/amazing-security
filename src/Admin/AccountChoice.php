<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

/** Plain account label for session and incident pickers. */
final class AccountChoice {
	public static function label( string $login, string $display ): string {
		$login   = trim( $login );
		$display = trim( $display );
		if ( '' === $login ) {
			return '';
		}
		if ( '' === $display || 0 === strcasecmp( $display, $login ) ) {
			return $login;
		}
		return $display . ' (' . $login . ')';
	}
}
