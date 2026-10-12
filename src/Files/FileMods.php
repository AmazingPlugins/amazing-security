<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Files;

/** Honors the site's file-modification lock (DISALLOW_FILE_MODS and the file_mod_allowed filter) for every action that changes files. */
final class FileMods {
	public static function allowed(): bool {
		if ( function_exists( 'wp_is_file_mod_allowed' ) ) {
			return (bool) wp_is_file_mod_allowed( 'amazing_security' );
		}
		return ! ( defined( 'DISALLOW_FILE_MODS' ) && true === DISALLOW_FILE_MODS );
	}

	public static function denial(): string {
		return __( 'This site blocks file changes (DISALLOW_FILE_MODS). Amazing Security will not change files while that lock is on. No file was changed.', 'amazing-security' );
	}

	/** Stop a request that would change files when the site has locked file changes. */
	public static function requireAllowed(): void {
		if ( ! self::allowed() ) {
			wp_die( esc_html( self::denial() ), '', array( 'response' => 403 ) );
		}
	}
}
