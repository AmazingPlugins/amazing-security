<?php
/**
 * Plugin Name: Ironlatch Security Scanner & AI Assistant Reviewer
 * Plugin URI: https://amazingplugins.com/plugins/ironlatch-security-scanner/
 * Description: Local WordPress security checks and optional login protection.
 * Version: 0.1.11
 * Requires at least: 6.6
 * Requires PHP: 8.1
 * Author: Amazing Plugins
 * Author URI: https://amazingplugins.com/
 * License: GPL-2.0-or-later
 * Text Domain: ironlatch-security-scanner
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IRONLATCH_SECURITY_SCANNER_FILE', __FILE__ );
define( 'IRONLATCH_SECURITY_SCANNER_DIR', plugin_dir_path( __FILE__ ) );
define( 'IRONLATCH_SECURITY_SCANNER_URL', plugin_dir_url( __FILE__ ) );

add_filter(
	'map_meta_cap',
	static function ( array $caps, string $cap ): array {
		// Same effect as DISALLOW_FILE_EDIT, limited to the editor capabilities and only after an administrator approved it.
		if ( in_array( $cap, array( 'edit_files', 'edit_plugins', 'edit_themes' ), true ) && '1' === get_option( 'ironlatch_disallow_file_edit', '0' ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	},
	10,
	2
);

add_filter(
	'wp_is_application_passwords_available',
	static function ( mixed $available ): mixed {
		return '1' === get_option( 'ironlatch_disable_application_passwords', '0' ) ? false : $available;
	}
);
add_filter(
	'wp_is_application_passwords_available_for_user',
	static function ( mixed $available ): mixed {
		return '1' === get_option( 'ironlatch_disable_application_passwords', '0' ) ? false : $available;
	}
);

spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'AmazingPlugins\\Security\\';
		if ( ! str_starts_with( $class_name, $prefix ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		$path     = IRONLATCH_SECURITY_SCANNER_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( is_file( $path ) ) {
			require $path;
		}
	}
);

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Login\WordPressRateCounterStore::class, 'install' ) );
register_activation_hook( __FILE__, array( AmazingPlugins\Security\Fixes\FixTables::class, 'install' ) );
register_activation_hook( __FILE__, array( AmazingPlugins\Security\Activity\ActivityTables::class, 'install' ) );
add_action( 'admin_enqueue_scripts', array( AmazingPlugins\Security\Admin\FirstRun::class, 'assets' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'ironlatch_login_cleanup' );
		wp_clear_scheduled_hook( 'ironlatch_fix_cleanup' );
		wp_clear_scheduled_hook( 'ironlatch_activity_cleanup' );
		( new AmazingPlugins\Security\Schedule\ScheduleHooks() )->clear();
		( new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->purge();
	}
);
add_action(
	'ironlatch_login_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Login\WordPressRateCounterStore( $GLOBALS['wpdb'] ) )->clearExpired( time() );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Login\WordPressRateCounterStore::class, 'ensureScheduled' ) );
add_action( 'init', array( AmazingPlugins\Security\Fixes\FixTables::class, 'ensureScheduled' ) );
add_action( 'init', array( AmazingPlugins\Security\Activity\ActivityTables::class, 'ensureScheduled' ) );
add_action(
	'ironlatch_activity_cleanup',
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
			$hook = 'integrity' === $status['stage'] ? 'ironlatch_integrity_tick' : 'ironlatch_file_tick';
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_single_event( time() + 60, $hook );
			}
		}
	}
);
add_action(
	'ironlatch_local_daily_scan',
	static function (): void {
		$options  = new AmazingPlugins\Security\Integrity\WordPressOptions();
		$schedule = new AmazingPlugins\Security\Schedule\LocalSchedule( $options );
		$success  = $schedule->tick( time() );
		$cycle    = new AmazingPlugins\Security\Schedule\SuiteCycle( $options );
		if ( $success && 'complete' === $schedule->status( time() )['state'] && $cycle->start( time() ) ) {
			wp_schedule_single_event( time() + 60, 'ironlatch_integrity_tick' );
		}
	}
);
add_action( 'ironlatch_integrity_tick', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'scheduled' ) );
add_action( 'ironlatch_file_tick', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'scheduled' ) );
add_action( AmazingPlugins\Security\Scan\LocalCodeScan::TICK, array( AmazingPlugins\Security\Scan\LocalCodeScan::class, 'tick' ) );
add_action(
	'ironlatch_alert_retry',
	static function (): void {
		( new AmazingPlugins\Security\Alerts\WordPressAlertNotifier() )->delivery()->retry( time() );
	}
);
add_action(
	'ironlatch_fix_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
	}
);
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'ironlatch_login_schema_version' ) ) {
			AmazingPlugins\Security\Login\WordPressRateCounterStore::install();
		}
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'ironlatch_activity_schema_version' ) ) {
			AmazingPlugins\Security\Activity\ActivityTables::install();
		}
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'ironlatch_fix_schema_version' ) ) {
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
		$confirm = new AmazingPlugins\Security\Login\LoginConfirmation( static fn(): bool => '1' === get_option( 'ironlatch_login_confirm', '0' ) );
		add_action( 'login_form', array( $confirm, 'render' ) );
		add_filter( 'authenticate', array( $confirm, 'authenticate' ), 26, 3 );
		$hints = new AmazingPlugins\Security\Login\LoginHints( static fn(): bool => '1' === get_option( 'ironlatch_generic_login_errors', '0' ) );
		add_filter( 'wp_login_errors', array( $hints, 'errors' ) );
		$exposure = new AmazingPlugins\Security\Login\AccountExposure(
			static fn(): bool => '1' === get_option( 'ironlatch_hide_author_archives', '0' ),
			static fn(): bool => '1' === get_option( 'ironlatch_hide_rest_users', '0' )
		);
		add_action( 'template_redirect', array( $exposure, 'redirect' ) );
		add_filter( 'rest_pre_dispatch', array( $exposure, 'rest' ), 6, 3 );
		$meta = new AmazingPlugins\Security\Hardening\PublicMeta(
			static fn(): bool => '1' === get_option( 'ironlatch_hide_generator', '0' ),
			static fn(): bool => '1' === get_option( 'ironlatch_hide_discovery_links', '0' )
		);
		add_filter( 'the_generator', array( $meta, 'generator' ) );
		add_action( 'init', array( $meta, 'discovery' ) );
		$passwords = new AmazingPlugins\Security\Login\CommonPasswordHooks( static fn(): bool => '1' === get_option( 'ironlatch_common_passwords', '0' ) );
		add_action( 'user_profile_update_errors', array( $passwords, 'profile' ), 10, 3 );
		add_filter( 'registration_errors', array( $passwords, 'registration' ), 10, 3 );
		add_action( 'validate_password_reset', array( $passwords, 'reset' ), 10, 2 );
		// Own TOTP second-step login is retired; detect-only status lives on Log In & Register.
		add_filter( 'xmlrpc_enabled', array( new AmazingPlugins\Security\Login\XmlRpcPolicy( $settings ), 'enabled' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			$recovery = new AmazingPlugins\Security\Login\LoginRecoveryCommand();
			\WP_CLI::add_command( 'ironlatch-security-scanner login disable', array( $recovery, 'disableLogin' ) );
			\WP_CLI::add_command( 'ironlatch-security-scanner totp disable', array( $recovery, 'disableTotp' ) );
		}
	}
);

add_action( 'plugins_loaded', array( AmazingPlugins\Security\Free\FreeSuite::class, 'boot' ), 20 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\AdminPage(), 'register' ) );
add_action( 'admin_post_ironlatch_uploads_rule', array( new AmazingPlugins\Security\Admin\UploadsRulePage(), 'save' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\FixReviewPage(), 'register' ) );
add_action( 'admin_post_ironlatch_findings_report', array( new AmazingPlugins\Security\Admin\FindingsReportAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_approved_setting', array( new AmazingPlugins\Security\Admin\ApprovedSettingAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_fix_approve', array( new AmazingPlugins\Security\Admin\FixApprovalAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_fix_rollback', array( new AmazingPlugins\Security\Admin\FixRollbackAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_security_scanner_scan', array( new AmazingPlugins\Security\Admin\ScanAction(), 'handle' ) );
add_action( 'wp_ajax_ironlatch_scan_step', array( new AmazingPlugins\Security\Admin\ScanStepAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_security_scanner_integrity_start', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'start' ) );
add_action( 'admin_post_ironlatch_security_scanner_integrity_resume', array( new AmazingPlugins\Security\Admin\IntegrityScanAction(), 'resume' ) );
add_action( 'admin_post_ironlatch_security_scanner_file_scan_start', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'start' ) );
add_action( 'admin_post_ironlatch_security_scanner_file_scan_resume', array( new AmazingPlugins\Security\Admin\FileScanAction(), 'resume' ) );
add_action( 'admin_post_ironlatch_security_scanner_file_scan_note', array( new AmazingPlugins\Security\Admin\FileScanReviewAction(), 'note' ) );
add_action( 'admin_post_ironlatch_security_scanner_vulnerability_scan', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_security_scanner_vulnerability_enable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'enable' ) );
add_action( 'admin_post_ironlatch_security_scanner_vulnerability_disable', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'disable' ) );
add_action( 'admin_post_ironlatch_security_scanner_vulnerability_clear', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'clearReports' ) );
add_action( 'admin_post_ironlatch_security_scanner_kev_toggle', array( new AmazingPlugins\Security\Admin\VulnerabilityConsentAction(), 'exploited' ) );
add_action( 'admin_post_ironlatch_login_settings', array( new AmazingPlugins\Security\Admin\LoginSettingsAction(), 'save' ) );
add_action( 'admin_post_ironlatch_mcp_settings', array( new AmazingPlugins\Security\Admin\McpSettingsAction(), 'save' ) );
add_action( 'admin_post_ironlatch_alert_settings', array( new AmazingPlugins\Security\Admin\AlertSettingsAction(), 'save' ) );
add_action( 'admin_post_ironlatch_scan_options', array( AmazingPlugins\Security\Admin\ScanOptions::class, 'save' ) );
add_action( 'admin_post_ironlatch_notification_test', array( new AmazingPlugins\Security\Admin\NotificationTestAction(), 'handle' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Admin\NotificationSettingsPage(), 'register' ), 20 );
add_action( 'admin_post_ironlatch_totp_begin', array( new AmazingPlugins\Security\Admin\TotpAction(), 'begin' ) );
add_action( 'admin_post_ironlatch_totp_confirm', array( new AmazingPlugins\Security\Admin\TotpAction(), 'confirm' ) );
add_action( 'admin_post_ironlatch_totp_disable', array( new AmazingPlugins\Security\Admin\TotpAction(), 'disable' ) );
add_action( 'admin_post_ironlatch_totp_regenerate', array( new AmazingPlugins\Security\Admin\TotpAction(), 'regenerate' ) );
add_action( 'ironlatch_vuln_tick', array( new AmazingPlugins\Security\Admin\VulnerabilityScanAction(), 'scheduled' ) );
add_filter( 'rest_pre_dispatch', array( new AmazingPlugins\Security\Firewall\RestFirewallHook(), 'filter' ), 5, 3 );

$ironlatch_fix_repository = new AmazingPlugins\Security\Fixes\WordPressFixRepository( $GLOBALS['wpdb'] );
$ironlatch_abilities      = new AmazingPlugins\Security\Mcp\AbilityRegistrar(
	new AmazingPlugins\Security\Mcp\McpPreferences( new AmazingPlugins\Security\Integrity\WordPressOptions() ),
	new AmazingPlugins\Security\Mcp\FindingsGateway(),
	new AmazingPlugins\Security\Mcp\ScanGateway( new AmazingPlugins\Security\Integrity\WordPressOptions() ),
	null,
	null,
	new AmazingPlugins\Security\Fixes\FixProposalService( $ironlatch_fix_repository ),
	new AmazingPlugins\Security\Mcp\FixGateway( $ironlatch_fix_repository )
);
add_action( 'wp_abilities_api_categories_init', array( $ironlatch_abilities, 'registerCategory' ) );
add_action( 'wp_abilities_api_init', array( $ironlatch_abilities, 'registerAbilities' ) );

( new AmazingPlugins\Security\Activity\ActivityHooks( new AmazingPlugins\Security\Activity\ActivityRepository( $GLOBALS['wpdb'] ) ) )->register();
add_action( 'admin_menu', array( new AmazingPlugins\Security\Activity\ActivityPage(), 'register' ) );
// admin-post.php never runs admin_menu, so form handlers register here.
add_action( 'admin_post_ironlatch_activity_recording', array( new AmazingPlugins\Security\Activity\ActivityPage(), 'save' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Sessions\SessionPage(), 'register' ) );
add_action( 'admin_post_ironlatch_sessions_revoke', array( new AmazingPlugins\Security\Sessions\SessionAction(), 'handle' ) );

$ironlatch_reset = new AmazingPlugins\Security\Incident\ResetRequirement();
add_filter( 'authenticate', array( $ironlatch_reset, 'authenticate' ), 28, 3 );
add_action( 'after_password_reset', array( $ironlatch_reset, 'passwordReset' ), 10, 1 );
add_action( 'profile_update', array( $ironlatch_reset, 'profileUpdated' ), 10, 2 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Incident\IncidentPage(), 'register' ) );
add_action( 'admin_post_ironlatch_incident_reset', array( new AmazingPlugins\Security\Incident\IncidentAction(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'ironlatch-security-scanner accounts clear-reset', array( $ironlatch_reset, 'recovery' ) );
}

$ironlatch_policy = new AmazingPlugins\Security\Login\RequiredTotpPolicy();
// Required TOTP policy login gate retired; WP-CLI cleanup remains.
add_action( 'admin_post_ironlatch_totp_policy', array( new AmazingPlugins\Security\Login\RequiredTotpAction(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'ironlatch-security-scanner policy disable', array( $ironlatch_policy, 'recovery' ) );
}

add_action( 'admin_menu', array( new AmazingPlugins\Security\Baseline\BaselinePage(), 'register' ) );
add_action( 'admin_post_ironlatch_baseline', array( new AmazingPlugins\Security\Baseline\BaselineAction(), 'handle' ) );

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Bots\BotCounterStore::class, 'install' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'ironlatch_bot_cleanup' );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Bots\BotCounterStore::class, 'ensureScheduled' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( AmazingPlugins\Security\Bots\BotCounterStore::SCHEMA !== get_option( 'ironlatch_bot_schema_version' ) ) {
			AmazingPlugins\Security\Bots\BotCounterStore::install(); }
	}
);
add_action(
	'ironlatch_bot_cleanup',
	static function (): void {
		( new AmazingPlugins\Security\Bots\BotCounterStore( $GLOBALS['wpdb'] ) )->cleanup( time() );
	}
);
$ironlatch_bots = new AmazingPlugins\Security\Bots\BotHooks();
add_action( 'comment_form_after_fields', array( $ironlatch_bots, 'fields' ) );
add_action( 'register_form', array( $ironlatch_bots, 'fields' ) );
add_filter( 'preprocess_comment', array( $ironlatch_bots, 'comment' ) );
add_filter( 'registration_errors', array( $ironlatch_bots, 'registration' ), 20, 1 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Bots\BotSettings(), 'register' ) );
$ironlatch_scanner = new AmazingPlugins\Security\Bots\ScannerGuard();
add_action( 'template_redirect', array( $ironlatch_scanner, 'check' ), 0 );
add_action( 'admin_post_ironlatch_scanner_guard', array( $ironlatch_scanner, 'handle' ) );
$ironlatch_rate = new AmazingPlugins\Security\Bots\RateLimiter();
add_action( 'init', array( $ironlatch_rate, 'check' ), 0 );
add_action( 'admin_post_ironlatch_rate_limits', array( $ironlatch_rate, 'handle' ) );
add_action( 'admin_post_ironlatch_bot_settings', array( new AmazingPlugins\Security\Bots\BotSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'ironlatch-security-scanner bots disable', array( new AmazingPlugins\Security\Bots\BotSettings(), 'recovery' ) );
}

$ironlatch_digest = new AmazingPlugins\Security\Digest\DigestHooks();
add_action( 'init', array( $ironlatch_digest, 'ensure' ) );
add_action( 'ironlatch_weekly_digest_tick', array( $ironlatch_digest, 'tick' ) );
register_deactivation_hook( __FILE__, array( $ironlatch_digest, 'clear' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Digest\DigestSettings(), 'register' ) );
add_action( 'admin_post_ironlatch_digest_settings', array( new AmazingPlugins\Security\Digest\DigestSettings(), 'handle' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Content\ContentPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Rules\RulePage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Repository\DirectoryPage(), 'register' ) );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Exposure\ExposurePage(), 'register' ) );
add_action( 'admin_post_ironlatch_exposure_inventory', array( new AmazingPlugins\Security\Exposure\ExposureAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_repository_lookup', array( new AmazingPlugins\Security\Repository\DirectoryAction(), 'handle' ) );
add_action( 'admin_post_ironlatch_content_scan', array( new AmazingPlugins\Security\Content\ContentAction(), 'handle' ) );

add_action( 'admin_menu', array( new AmazingPlugins\Security\Headers\HeaderPage(), 'register' ) );
add_action( 'admin_post_ironlatch_headers_check', array( new AmazingPlugins\Security\Headers\HeaderAction(), 'handle' ) );

add_filter( 'rest_pre_dispatch', array( new AmazingPlugins\Security\Firewall\RestRateHook(), 'filter' ), 6, 3 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'register' ) );
add_action( 'admin_post_ironlatch_rest_rate_settings', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'ironlatch-security-scanner rest-rates disable', array( new AmazingPlugins\Security\Firewall\RestRateSettings(), 'recovery' ) ); }

add_action( 'init', array( new AmazingPlugins\Security\Network\NetworkHook(), 'handle' ), 5 );
add_action( 'admin_menu', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'register' ) );
add_action( 'admin_post_ironlatch_network_settings', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'ironlatch-security-scanner network disable', array( new AmazingPlugins\Security\Network\NetworkSettings(), 'recovery' ) ); }

register_activation_hook( __FILE__, array( AmazingPlugins\Security\Traffic\TrafficTables::class, 'install' ) );
register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'ironlatch_traffic_cleanup' );
	}
);
add_action( 'init', array( AmazingPlugins\Security\Traffic\TrafficTables::class, 'ensureScheduled' ) );
add_action(
	'admin_init',
	static function (): void {
		if ( current_user_can( 'manage_options' ) && '1' !== get_option( 'ironlatch_traffic_schema_version' ) ) {
			AmazingPlugins\Security\Traffic\TrafficTables::install(); }
	}
);
add_action(
	'ironlatch_traffic_cleanup',
	static function (): void {
		try {
			( new AmazingPlugins\Security\Traffic\TrafficRepository( $GLOBALS['wpdb'] ) )->cleanup( time() );
		} catch ( \Throwable ) {
			return; }
	}
);
AmazingPlugins\Security\Traffic\TrafficHooks::register();
add_action( 'admin_menu', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'register' ) );
add_action( 'admin_post_ironlatch_traffic_settings', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'ironlatch-security-scanner traffic disable', array( new AmazingPlugins\Security\Traffic\TrafficSettings(), 'recovery' ) ); }

add_action( 'admin_menu', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'register' ) );
add_action( 'admin_post_ironlatch_proxy_settings', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'handle' ) );
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'ironlatch-security-scanner proxies disable', array( new AmazingPlugins\Security\Proxy\ProxySettings(), 'recovery' ) ); }
