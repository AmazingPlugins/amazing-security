<?php
/**
 * Plugin Name: Amazing Security
 * Plugin URI: https://amazingplugins.com/plugins/amazing-security/
 * Description: Local WordPress security checks and optional login protection.
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

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Login\WordPressRateCounterStore::class, 'install' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_login_schema_version' ) ) {
			AmazingPlugins\Security\Login\WordPressRateCounterStore::install();
		}
	}
);

add_action(
	'plugins_loaded',
	static function (): void {
		$settings = new AmazingPlugins\Security\Login\WordPressLoginSettings( new AmazingPlugins\Security\Integrity\WordPressOptions() );
		$hooks    = new AmazingPlugins\Security\Login\LoginHooks(
			new AmazingPlugins\Security\Login\RateLimiter( $settings, new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) ),
			new AmazingPlugins\Security\Login\AddressKey( wp_salt( 'auth' ) )
		);
		add_filter( 'authenticate', array( $hooks, 'authenticate' ), 25, 3 );
		add_action( 'wp_login_failed', array( $hooks, 'failed' ), 10, 2 );
		$totp = new AmazingPlugins\Security\Login\TotpAuthentication(
			new AmazingPlugins\Security\Login\WordPressTotpStore( $GLOBALS['wpdb'] ),
			new AmazingPlugins\Security\Login\SecretCipher( wp_salt( 'auth' ) ),
			new AmazingPlugins\Security\Login\Totp()
		);
		add_filter( 'authenticate', array( $totp, 'authenticate' ), 30, 3 );
		$fields = new AmazingPlugins\Security\Login\LoginFormFields();
		add_action( 'login_form', array( $fields, 'render' ) );
		add_action( 'woocommerce_login_form', array( $fields, 'render' ) );
		add_filter( 'xmlrpc_enabled', array( new AmazingPlugins\Security\Login\XmlRpcPolicy( $settings ), 'enabled' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			$recovery = new AmazingPlugins\Security\Login\LoginRecoveryCommand();
			\WP_CLI::add_command( 'amazing-security login disable', array( $recovery, 'disableLogin' ) );
			\WP_CLI::add_command( 'amazing-security totp disable', array( $recovery, 'disableTotp' ) );
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
add_action( 'admin_post_amsec_login_settings', array( new AmazingPlugins\Security\Admin\LoginSettingsAction(), 'save' ) );
add_action( 'admin_post_amsec_totp_begin', array( new AmazingPlugins\Security\Admin\TotpAction(), 'begin' ) );
add_action( 'admin_post_amsec_totp_confirm', array( new AmazingPlugins\Security\Admin\TotpAction(), 'confirm' ) );
add_action( 'admin_post_amsec_totp_disable', array( new AmazingPlugins\Security\Admin\TotpAction(), 'disable' ) );
add_action( 'admin_post_amsec_totp_regenerate', array( new AmazingPlugins\Security\Admin\TotpAction(), 'regenerate' ) );
add_action( 'amsec_vuln_tick', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'scheduled' ) );
