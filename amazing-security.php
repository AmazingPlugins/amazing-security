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

$amsec_file_editor = get_option( 'amsec_disallow_file_edit', '0' );
if ( '1' === $amsec_file_editor && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
	define( 'DISALLOW_FILE_EDIT', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- This is the WordPress core file-editor constant.
}
if ( '1' === get_option( 'amsec_hide_debug_display', '0' ) ) {
	// phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed, PluginCheck.CodeAnalysis.PHPErrorReporting.IniDirectiveDisplay_errors, Squiz.PHP.DiscouragedFunctions.Discouraged -- Approved display hide. This does not edit wp-config.php.
	ini_set( 'display_errors', '0' );
}

add_filter(
	'wp_is_application_passwords_available',
	static function ( mixed $available ): mixed {
		return '1' === get_option( 'amsec_disable_application_passwords', '0' ) ? false : $available;
	}
);
add_filter(
	'wp_is_application_passwords_available_for_user',
	static function ( mixed $available ): mixed {
		return '1' === get_option( 'amsec_disable_application_passwords', '0' ) ? false : $available;
	}
);

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
register_activation_hook( __FILE__, array( AmazingPlugins\Security\Fixes\FixTables::class, 'install' ) );
register_activation_hook( __FILE__, array( AmazingPlugins\Security\Activity\ActivityTables::class, 'install' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'amsec_login_cleanup' );
		wp_clear_scheduled_hook( 'amsec_fix_cleanup' );
		wp_clear_scheduled_hook( 'amsec_activity_cleanup' );
		( new AmazingPlugins\Security\Schedule\ScheduleHooks() )->clear();
		( new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->purge();
	}
);
add_action(
	'amsec_login_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->clearExpired( time() );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Login\WordPressRateCounterStore::class, 'ensureScheduled' ) );
add_action( 'init', array( AmazingPlugins\Security\Fixes\FixTables::class, 'ensureScheduled' ) );
add_action( 'init', array( AmazingPlugins\Security\Activity\ActivityTables::class, 'ensureScheduled' ) );
add_action(
	'amsec_activity_cleanup',
	static function (): void {
		try {
			( new AmazingPlugins\Security\Activity\ActivityRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
		} catch ( \RuntimeException ) {
			// Retry next cleanup.
			return;
		}
	}
);
add_action(
	'init',
	static function (): void {
		( new AmazingPlugins\Security\Schedule\ScheduleHooks() )->ensure();
		$cycle  = new AmazingPlugins\Security\Schedule\SuiteCycle( new AmazingPlugins\Security\Integrity\WordPressOptions() );
		$status = $cycle->status( time() );
		if ( 'running' === $status['state'] && (int) ( $status['lease_until'] ?? 0 ) <= time() ) {
			$hook = 'integrity' === $status['stage'] ? 'amsec_integrity_tick' : 'amsec_file_tick';
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_single_event( time() + 60, $hook );
			}
		}
	}
);
add_action(
	'amsec_local_daily_scan',
	static function (): void {
		$options  = new AmazingPlugins\Security\Integrity\WordPressOptions();
		$schedule = new AmazingPlugins\Security\Schedule\LocalSchedule( $options );
		$success  = $schedule->tick( time() );
		$cycle    = new AmazingPlugins\Security\Schedule\SuiteCycle( $options );
		if ( $success && 'complete' === $schedule->status( time() )['state'] && $cycle->start( time() ) ) {
			wp_schedule_single_event( time() + 60, 'amsec_integrity_tick' );
		}
	}
);
add_action( 'amsec_integrity_tick', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'scheduled' ) );
add_action( 'amsec_file_tick', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'scheduled' ) );
add_action(
	'amsec_alert_retry',
	static function (): void {
		( new AmazingPlugins\Security\Alerts\WordPressAlertNotifier() )->delivery()->retry( time() );
	}
);
add_action(
	'amsec_fix_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
	}
);
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_login_schema_version' ) ) {
			AmazingPlugins\Security\Login\WordPressRateCounterStore::install();
		}
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_activity_schema_version' ) ) {
			AmazingPlugins\Security\Activity\ActivityTables::install();
		}
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_fix_schema_version' ) ) {
			AmazingPlugins\Security\Fixes\FixTables::install();
		}
	}
);

add_action(
	'plugins_loaded',
	static function (): void {
		$settings = new AmazingPlugins\Security\Login\WordPressLoginSettings( new AmazingPlugins\Security\Integrity\WordPressOptions() );
		$hooks    = new AmazingPlugins\Security\Login\LoginHooks(
			new AmazingPlugins\Security\Login\RateLimiter( $settings, new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) ),
			( new AmazingPlugins\Security\Proxy\WordPressClientAddress() )->key( wp_salt( 'auth' ) )
		);
		add_filter( 'authenticate', array( $hooks, 'authenticate' ), 25, 3 );
		add_action( 'wp_login_failed', array( $hooks, 'failed' ), 10, 2 );
		$confirm = new AmazingPlugins\Security\Login\LoginConfirmation( static fn(): bool => '1' === get_option( 'amsec_login_confirm', '0' ) );
		add_action( 'login_form', array( $confirm, 'render' ) );
		add_filter( 'authenticate', array( $confirm, 'authenticate' ), 26, 3 );
		$hints = new AmazingPlugins\Security\Login\LoginHints( static fn(): bool => '1' === get_option( 'amsec_generic_login_errors', '0' ) );
		add_filter( 'wp_login_errors', array( $hints, 'errors' ) );
		$exposure = new AmazingPlugins\Security\Login\AccountExposure(
			static fn(): bool => '1' === get_option( 'amsec_hide_author_archives', '0' ),
			static fn(): bool => '1' === get_option( 'amsec_hide_rest_users', '0' )
		);
		add_action( 'template_redirect', array( $exposure, 'redirect' ) );
		add_filter( 'rest_pre_dispatch', array( $exposure, 'rest' ), 6, 3 );
		$meta = new AmazingPlugins\Security\Hardening\PublicMeta(
			static fn(): bool => '1' === get_option( 'amsec_hide_generator', '0' ),
			static fn(): bool => '1' === get_option( 'amsec_hide_discovery_links', '0' )
		);
		add_filter( 'the_generator', array( $meta, 'generator' ) );
		add_action( 'init', array( $meta, 'discovery' ) );
		$passwords = new AmazingPlugins\Security\Login\CommonPasswordHooks( static fn(): bool => '1' === get_option( 'amsec_common_passwords', '0' ) );
		add_action( 'user_profile_update_errors', array( $passwords, 'profile' ), 10, 3 );
		add_filter( 'registration_errors', array( $passwords, 'registration' ), 10, 3 );
		add_action( 'validate_password_reset', array( $passwords, 'reset' ), 10, 2 );
		// Own TOTP second-step login is retired; detect-only status lives on Log In & Register.
		add_filter( 'xmlrpc_enabled', array( new AmazingPlugins\Security\Login\XmlRpcPolicy( $settings ), 'enabled' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			$recovery = new AmazingPlugins\Security\Login\LoginRecoveryCommand();
			\WP_CLI::add_command( 'amazing-security login disable', array( $recovery, 'disableLogin' ) );
			\WP_CLI::add_command( 'amazing-security totp disable', array( $recovery, 'disableTotp' ) );
			\WP_CLI::add_command( 'amazing-security repair rollback', array( new AmazingPlugins\Security\Repair\RepairRecoveryCommand(), 'rollback' ) );
			\WP_CLI::add_command( 'amazing-security repair recover', array( new AmazingPlugins\Security\Repair\RepairRecoveryCommand(), 'recover' ) );
		}
	}
);

add_action( 'plugins_loaded', array( AmazingPlugins\Security\Free\FreeSuite::class, 'boot' ), 20 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\AdminPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\FixReviewPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\RepairPage(), 'register' ) );
add_action( 'admin_post_amsec_findings_report', array( new AmazingPlugins\Security\Admin\FindingsReportAction(), 'handle' ) );
add_action( 'admin_post_amsec_approved_setting', array( new AmazingPlugins\Security\Admin\ApprovedSettingAction(), 'handle' ) );
add_action( 'admin_post_amsec_fix_approve', array( new AmazingPlugins\Security\Admin\FixApprovalAction(), 'handle' ) );
add_action( 'admin_post_amsec_fix_rollback', array( new AmazingPlugins\Security\Admin\FixRollbackAction(), 'handle' ) );
add_action( 'admin_post_amsec_repair_apply', array( new AmazingPlugins\Security\Admin\RepairAction(), 'apply' ) );
add_action( 'admin_post_amsec_repair_rollback', array( new AmazingPlugins\Security\Admin\RepairAction(), 'rollback' ) );
add_action( 'admin_post_amsec_repair_retire', array( new AmazingPlugins\Security\Admin\RepairAction(), 'retire' ) );
add_action( 'admin_post_amazing_security_scan', array( new AmazingPlugins\Security\Admin\ScanAction(), 'handle' ) );
add_action( 'admin_post_amazing_security_integrity_start', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'start' ) );
add_action( 'admin_post_amazing_security_integrity_resume', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'resume' ) );
add_action( 'admin_post_amazing_security_file_scan_start', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'start' ) );
add_action( 'admin_post_amazing_security_file_scan_resume', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'resume' ) );
add_action( 'admin_post_amazing_security_file_scan_note', array( new AmazingPlugins\Security\Admin\FileScanReviewAction(), 'note' ) );
add_action( 'admin_post_amazing_security_vulnerability_scan', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'handle' ) );
add_action( 'admin_post_amazing_security_vulnerability_enable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'enable' ) );
add_action( 'admin_post_amazing_security_vulnerability_disable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'disable' ) );
add_action( 'admin_post_amazing_security_vulnerability_clear', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'clearReports' ) );
add_action( 'admin_post_amsec_login_settings', array( new AmazingPlugins\Security\Admin\LoginSettingsAction(), 'save' ) );
add_action( 'admin_post_amsec_mcp_settings', array( new AmazingPlugins\Security\Admin\McpSettingsAction(), 'save' ) );
add_action( 'admin_post_amsec_alert_settings', array( new AmazingPlugins\Security\Admin\AlertSettingsAction(), 'save' ) );
add_action( 'admin_post_amsec_notification_test', array( new AmazingPlugins\Security\Admin\NotificationTestAction(), 'handle' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\NotificationSettingsPage(), 'register' ), 20 );
add_action( 'admin_post_amsec_totp_begin', array( new AmazingPlugins\Security\Admin\TotpAction(), 'begin' ) );
add_action( 'admin_post_amsec_totp_confirm', array( new AmazingPlugins\Security\Admin\TotpAction(), 'confirm' ) );
add_action( 'admin_post_amsec_totp_disable', array( new AmazingPlugins\Security\Admin\TotpAction(), 'disable' ) );
add_action( 'admin_post_amsec_totp_regenerate', array( new AmazingPlugins\Security\Admin\TotpAction(), 'regenerate' ) );
add_action( 'amsec_vuln_tick', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'scheduled' ) );
add_filter( 'rest_pre_dispatch', array( new AmazingPlugins\Security\Firewall\RestFirewallHook(), 'filter' ), 5, 3 );

$amsec_fix_repository = new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS['wpdb'] );
$amsec_abilities      = new AmazingPlugins\Security\Mcp\AbilityRegistrar(
	new AmazingPlugins\Security\Mcp\McpPreferences( new AmazingPlugins\Security\Integrity\WordPressOptions() ),
	new AmazingPlugins\Security\Mcp\FindingsGateway(),
	new AmazingPlugins\Security\Mcp\ScanGateway( new AmazingPlugins\Security\Integrity\WordPressOptions() ),
	null,
	null,
	new AmazingPlugins\Security\Fixes\FixProposalService( $amsec_fix_repository ),
	new AmazingPlugins\Security\Mcp\FixGateway( $amsec_fix_repository )
);
add_action( 'wp_abilities_api_categories_init', array( $amsec_abilities, 'registerCategory' ) );
add_action( 'wp_abilities_api_init', array( $amsec_abilities, 'registerAbilities' ) );

( new AmazingPlugins\Security\Activity\ActivityHooks( new AmazingPlugins\Security\Activity\ActivityRepository( $GLOBALS['wpdb'] ) ) )->register();
add_action( 'admin_menu', array( new AmazingPlugins\Security\Activity\ActivityPage(), 'register' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Sessions\SessionPage(), 'register' ) );
add_action( 'admin_post_amsec_sessions_revoke', array( new AmazingPlugins\Security\Sessions\SessionAction(), 'handle' ) );

$amsec_reset = new AmazingPlugins\Security\Incident\ResetRequirement();
add_filter( 'authenticate', array( $amsec_reset, 'authenticate' ), 28, 3 );
add_action( 'after_password_reset', array( $amsec_reset, 'passwordReset' ), 10, 1 );
add_action( 'profile_update', array( $amsec_reset, 'profileUpdated' ), 10, 2 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Incident\IncidentPage(), 'register' ) );
add_action( 'admin_post_amsec_incident_reset', array( new AmazingPlugins\Security\Incident\IncidentAction(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'amazing-security accounts clear-reset', array( $amsec_reset, 'recovery' ) );
}

$amsec_policy = new AmazingPlugins\Security\Login\RequiredTotpPolicy();
// Required TOTP policy login gate retired; WP-CLI cleanup remains.
add_action( 'admin_post_amsec_totp_policy', array( new AmazingPlugins\Security\Login\RequiredTotpAction(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'amazing-security policy disable', array( $amsec_policy, 'recovery' ) );
}

add_action( 'admin_menu', array( new AmazingPlugins\Security\Baseline\BaselinePage(), 'register' ) );
add_action( 'admin_post_amsec_baseline', array( new AmazingPlugins\Security\Baseline\BaselineAction(), 'handle' ) );

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Bots\BotCounterStore::class, 'install' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'amsec_bot_cleanup' );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Bots\BotCounterStore::class, 'ensureScheduled' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( '1' !== get_option( 'amsec_bot_schema_version' ) ) {
			AmazingPlugins\Security\Bots\BotCounterStore::install(); }
	}
);
add_action(
	'amsec_bot_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Bots\BotCounterStore( $GLOBALS['wpdb'] ) )->cleanup( time() );
	}
);
$amsec_bots = new AmazingPlugins\Security\Bots\BotHooks();
add_action( 'comment_form_after_fields', array( $amsec_bots, 'fields' ) );
add_action( 'register_form', array( $amsec_bots, 'fields' ) );
add_filter( 'preprocess_comment', array( $amsec_bots, 'comment' ) );
add_filter( 'registration_errors', array( $amsec_bots, 'registration' ), 20, 1 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Bots\BotSettings(), 'register' ) );
add_action( 'admin_post_amsec_bot_settings', array( new AmazingPlugins\Security\Bots\BotSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'amazing-security bots disable', array( new AmazingPlugins\Security\Bots\BotSettings(), 'recovery' ) );
}

$amsec_digest = new AmazingPlugins\Security\Digest\DigestHooks();
add_action( 'init', array( $amsec_digest, 'ensure' ) );
add_action( 'amsec_weekly_digest_tick', array( $amsec_digest, 'tick' ) );
register_deactivation_hook( __FILE__, array( $amsec_digest, 'clear' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Digest\DigestSettings(), 'register' ) );
add_action( 'admin_post_amsec_digest_settings', array( new AmazingPlugins\Security\Digest\DigestSettings(), 'handle' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Content\ContentPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Rules\RulePage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Repository\DirectoryPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Exposure\ExposurePage(), 'register' ) );
add_action( 'admin_post_amsec_exposure_inventory', array( new AmazingPlugins\Security\Exposure\ExposureAction(), 'handle' ) );
add_action( 'admin_post_amsec_repository_lookup', array( new AmazingPlugins\Security\Repository\DirectoryAction(), 'handle' ) );
add_action( 'admin_post_amsec_content_scan', array( new AmazingPlugins\Security\Content\ContentAction(), 'handle' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Headers\HeaderPage(), 'register' ) );
add_action( 'admin_post_amsec_headers_check', array( new AmazingPlugins\Security\Headers\HeaderAction(), 'handle' ) );

add_filter( 'rest_pre_dispatch', array( new AmazingPlugins\Security\Firewall\RestRateHook(), 'filter' ), 6, 3 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'register' ) );
add_action( 'admin_post_amsec_rest_rate_settings', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'amazing-security rest-rates disable', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'recovery' ) ); }

add_action( 'init', array( new AmazingPlugins\Security\Network\NetworkHook(), 'handle' ), 5 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'register' ) );
add_action( 'admin_post_amsec_network_settings', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'amazing-security network disable', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'recovery' ) ); }

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Traffic\TrafficTables::class, 'install' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'amsec_traffic_cleanup' );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Traffic\TrafficTables::class, 'ensureScheduled' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_traffic_schema_version' ) ) {
			AmazingPlugins\Security\Traffic\TrafficTables::install(); }
	}
);
add_action(
	'amsec_traffic_cleanup',
	static function (): void {
		try {
			( new AmazingPlugins\Security\Traffic\TrafficRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
		} catch ( \Throwable ) {
			return; }
	}
);
AmazingPlugins\Security\Traffic\TrafficHooks::register();
add_action( 'admin_menu', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'register' ) );
add_action( 'admin_post_amsec_traffic_settings', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'amazing-security traffic disable', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'recovery' ) ); }

add_action( 'admin_menu', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'register' ) );
add_action( 'admin_post_amsec_proxy_settings', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'amazing-security proxies disable', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'recovery' ) ); }

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Passkeys\PasskeyTables::class, 'install' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'amsec_passkey_schema_version' ) ) {
			AmazingPlugins\Security\Passkeys\PasskeyTables::install();
		}
	}
);
add_action(
	'init',
	static function (): void {
		if ( '1' === get_option( 'amsec_passkey_schema_version' ) ) {
			AmazingPlugins\Security\Passkeys\PasskeyTables::ensureScheduled();
		}
	}
);
add_action(
	'amsec_passkey_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Passkeys\PasskeyRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
	}
);
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'amsec_passkey_cleanup' );
	}
);
add_action(
	'delete_user',
	static function ( int $id ): void {
		( new AmazingPlugins\Security\Passkeys\PasskeyRepository( $GLOBALS['wpdb'] ) )->revokeUser( $id );
	}
);
$amsec_passkey_settings = new AmazingPlugins\Security\Passkeys\PasskeySettings();
add_action( 'admin_menu', array( $amsec_passkey_settings, 'register' ) );
add_action( 'admin_post_amsec_passkey_settings', array( $amsec_passkey_settings, 'handle' ) );
// Own passkey enroll/login UI retired; status card is on Log In & Register. Cleanup CLI remains.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'amazing-security passkeys disable', array( $amsec_passkey_settings, 'recoveryDisable' ) );
	WP_CLI::add_command( 'amazing-security passkeys revoke', array( $amsec_passkey_settings, 'recoveryRevoke' ) );
}
add_action(
	'admin_post_amsec_passkey_enroll_begin',
	static function (): void {
		wp_die( esc_html__( 'Amazing Security no longer enrolls passkeys.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
);
add_action(
	'admin_post_amsec_passkey_enroll_finish',
	static function (): void {
		wp_die( esc_html__( 'Amazing Security no longer enrolls passkeys.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
);
add_action(
	'admin_post_amsec_passkey_remove',
	static function (): void {
		wp_die( esc_html__( 'Amazing Security no longer manages passkeys.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
);
add_action(
	'admin_post_nopriv_amsec_passkey_login_begin',
	static function (): void {
		wp_die( esc_html__( 'Amazing Security no longer provides passkey sign-in.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
);
add_action(
	'admin_post_nopriv_amsec_passkey_login_finish',
	static function (): void {
		wp_die( esc_html__( 'Amazing Security no longer provides passkey sign-in.', 'amazing-security' ), '', array( 'response' => 410 ) );
	}
);
