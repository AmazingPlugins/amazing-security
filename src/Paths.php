<?php
/**
 * Site and plugin locations in one place.
 *
 * @package ironlatch-security-scanner
 */

declare(strict_types=1);

namespace AmazingPlugins\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Paths {
	/**
	 * Folder that holds all plugins.
	 *
	 * shortcut: derived from this plugin's own path, so a symlinked plugin folder points elsewhere; upgrade only if someone reports it.
	 */
	public static function plugins(): string {
		return dirname( rtrim( IRONLATCH_SECURITY_SCANNER_DIR, '/\\' ) );
	}

	/** The wp-content folder. WordPress has no function that returns this path. */
	public static function content(): string {
		return rtrim( WP_CONTENT_DIR, '/' );
	}

	/** The must-use plugins folder, or an empty string. WordPress has no function that returns this path. */
	public static function muPlugins(): string {
		return defined( 'WPMU_PLUGIN_DIR' ) ? rtrim( WPMU_PLUGIN_DIR, '/' ) : '';
	}

	/** The WordPress install folder (wp-admin, wp-includes, license.txt). WordPress has no function that returns this path. */
	public static function core(): string {
		return ABSPATH;
	}

	/** The web root that holds index.php, robots.txt and llms.txt. */
	public static function home(): string {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return self::core(); // get_home_path() reads SCRIPT_FILENAME, which is the wp binary here.
		}
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return get_home_path();
	}
}
