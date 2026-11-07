<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Database;

defined( 'ABSPATH' ) || exit;

final class SchemaCheck {
	/** True only when every named table exists, so a failed dbDelta() is never recorded as installed. */
	public static function tablesExist( object $db, string ...$tables ): bool {
		foreach ( $tables as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- One-off install check on plugin-owned tables.
			$found = $db->get_var( $db->prepare( 'SHOW TABLES LIKE %s', $db->esc_like( $table ) ) );
			if ( ! is_string( $found ) || 0 !== strcasecmp( $found, $table ) ) {
				return false;
			}
		}
		return true;
	}

	/** Stores the schema version when the tables exist and clears it otherwise, so the next load retries the install. */
	public static function record( string $option, string $version, object $db, string ...$tables ): void {
		if ( self::tablesExist( $db, ...$tables ) ) {
			update_option( $option, $version, false );
			return;
		}
		delete_option( $option );
	}
}
