<?php
/**
 * Plugin Name: Amazing Security
 * Plugin URI: https://amazingplugins.com/plugins/amazing-security/
 * Description: Evidence-led, read-only WordPress security checks.
 * Version: 0.1.0
 * Requires at least: 6.6
 * Requires PHP: 8.1
 * Author: Amazing Plugins
 * Author URI: https://amazingplugins.com/
 * License: GPL-2.0-or-later
 * Text Domain: amazing-security
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AMAZING_SECURITY_FILE', __FILE__ );

spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'AmazingPlugins\\Security\\';
		if ( ! str_starts_with( $class_name, $prefix ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		$path     = __DIR__ . '/src/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( is_file( $path ) ) {
			require $path;
		}
	}
);

add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\AdminPage(), 'register' ) );
add_action( 'admin_post_amazing_security_scan', array( new AmazingPlugins\Security\Admin\ScanAction(), 'handle' ) );
add_action( 'admin_post_amazing_security_integrity_start', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'start' ) );
add_action( 'admin_post_amazing_security_integrity_resume', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'resume' ) );
add_action( 'admin_post_amazing_security_vulnerability_scan', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'handle' ) );
add_action( 'admin_post_amazing_security_vulnerability_enable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'enable' ) );
add_action( 'admin_post_amazing_security_vulnerability_disable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'disable' ) );
add_action( 'admin_post_amazing_security_vulnerability_clear', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'clearReports' ) );
add_action( 'amsec_vuln_tick', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'scheduled' ) );
