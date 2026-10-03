<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Scan;

use AmazingPlugins\Security\Checks\AiReadersCheck;
use AmazingPlugins\Security\Checks\AiReadinessCheck;
use AmazingPlugins\Security\Checks\KnownHolesCheck;
use AmazingPlugins\Security\Checks\AdminAccountsCheck;
use AmazingPlugins\Security\Checks\FileModesCheck;
use AmazingPlugins\Security\Checks\BotModeCheck;
use AmazingPlugins\Security\Checks\RestRateCheck;
use AmazingPlugins\Security\Checks\SiteWatchCheck;
use AmazingPlugins\Security\Checks\FilesystemPermissionsCheck;
use AmazingPlugins\Security\Checks\UploadsExecutionCheck;
use AmazingPlugins\Security\Checks\DebugDisplayCheck;
use AmazingPlugins\Security\Checks\FileEditorCheck;
use AmazingPlugins\Security\Checks\GapCheck;
use AmazingPlugins\Security\Checks\BackgroundUpdatesCheck;
use AmazingPlugins\Security\Checks\ConfigBackupCheck;
use AmazingPlugins\Security\Checks\DebugLogCheck;
use AmazingPlugins\Security\Checks\ErrorLogCheck;
use AmazingPlugins\Security\Checks\PackageUpdateCheck;
use AmazingPlugins\Security\Checks\PhpVersionCheck;
use AmazingPlugins\Security\Checks\SampleConfigCheck;
use AmazingPlugins\Security\Checks\InactivePluginsCheck;
use AmazingPlugins\Security\Checks\InactiveThemesCheck;
use AmazingPlugins\Security\Checks\UploadsPhpFilesCheck;
use AmazingPlugins\Security\Checks\LicenseFileCheck;
use AmazingPlugins\Security\Checks\LocalCodeCheck;
use AmazingPlugins\Security\Checks\RootExposureCheck;
use AmazingPlugins\Security\Checks\ReadmeFileCheck;
use AmazingPlugins\Security\Checks\FollowUpCheck;
use AmazingPlugins\Security\Checks\HttpsAdminCheck;
use AmazingPlugins\Security\Checks\LoginRateModeCheck;
use AmazingPlugins\Security\Checks\PingbackCheck;
use AmazingPlugins\Security\Checks\XmlRpcAuthCheck;
use AmazingPlugins\Security\Checks\UpdatePostureCheck;
use AmazingPlugins\Security\Checks\Values;
use AmazingPlugins\Security\Checks\WordPressValues;
use AmazingPlugins\Security\Findings\FindingsRepository;
use Closure;

final class LocalHardeningScanService {
	private readonly Closure $execute;
	private readonly Closure $save;

	public function __construct( ?callable $execute = null, ?callable $save = null ) {
		$this->execute = Closure::fromCallable(
			$execute ?? static function (): ScanRun {
				if ( function_exists( 'get_option' ) ) {
					( new LocalPass() )->advance();
				}
				$values   = new WordPressValues();
				$checks   = self::checks( $values, static fn(): mixed => get_option( 'amsec_login_rate_mode', null ) );
				$paths    = FilesystemPermissionsCheck::wordpressPaths();
				$checks[] = new FilesystemPermissionsCheck( $paths );
				$checks[] = new FileModesCheck( $paths );
				$checks[] = new UploadsExecutionCheck();
				$checks[] = new PingbackCheck( static fn(): mixed => get_option( 'default_ping_status', null ) );
				$checks[] = new XmlRpcAuthCheck( static fn(): mixed => get_option( 'amsec_login_xmlrpc_disabled', null ) );
				$checks[] = new GapCheck( 'captcha-login', static fn(): string => self::gateOption( 'amsec_login_confirm' ) );
				$checks[] = new GapCheck( 'compromised-passwords', static fn(): string => self::gateOption( 'amsec_common_passwords' ) );
				$checks[] = new GapCheck( 'login-hints', static fn(): string => self::gateOption( 'amsec_generic_login_errors' ) );
				$checks[] = new GapCheck( 'author-archives', static fn(): string => self::gateOption( 'amsec_hide_author_archives' ) );
				$checks[] = new GapCheck( 'rest-user-list', static fn(): string => self::gateOption( 'amsec_hide_rest_users' ) );
				$checks[] = new GapCheck( 'version-tag', static fn(): string => self::gateOption( 'amsec_hide_generator' ) );
				$checks[] = new GapCheck( 'discovery-links', static fn(): string => self::gateOption( 'amsec_hide_discovery_links' ) );
				$checks[] = new ReadmeFileCheck();
				$checks[] = new LicenseFileCheck();
				$checks[] = new DebugLogCheck();
				$checks[] = new SampleConfigCheck();
				$checks[] = new ErrorLogCheck();
				$checks[] = new ConfigBackupCheck();
				$checks[] = new PhpVersionCheck();
				$checks[] = new BackgroundUpdatesCheck();
				$checks[] = new PackageUpdateCheck( 'plugin-updates' );
				$checks[] = new PackageUpdateCheck( 'theme-updates' );
				$checks[] = new InactivePluginsCheck();
				$checks[] = new InactiveThemesCheck();
				$checks[] = new UploadsPhpFilesCheck();
				$checks[] = new RootExposureCheck();
				$checks[] = new BotModeCheck( static fn(): mixed => get_option( 'amsec_bot_mode', 'off' ) );
				$checks[] = new RestRateCheck( static fn(): mixed => get_option( 'amsec_rest_rate_policy', null ) );
				$checks[] = new SiteWatchCheck( 'finding-emails', array( SiteWatchCheck::class, 'findingEmails' ) );
				$checks[] = new SiteWatchCheck( 'weekly-digest', array( SiteWatchCheck::class, 'weeklyDigest' ) );
				$checks[] = new SiteWatchCheck( 'traffic-history', array( SiteWatchCheck::class, 'trafficHistory' ) );
				$checks[] = new SiteWatchCheck( 'network-controls', array( SiteWatchCheck::class, 'networkControls' ) );
				$checks[] = new SiteWatchCheck( 'trusted-proxies', array( SiteWatchCheck::class, 'trustedProxies' ) );
				$checks[] = new SiteWatchCheck( 'security-activity', array( SiteWatchCheck::class, 'securityActivity' ) );
				$checks[] = new SiteWatchCheck( 'account-sessions', array( SiteWatchCheck::class, 'accountSessions' ) );
				$checks[] = new SiteWatchCheck( 'code-baselines', array( SiteWatchCheck::class, 'codeBaselines' ) );
				$checks[] = new SiteWatchCheck( 'daily-checks', array( SiteWatchCheck::class, 'dailyChecks' ) );
				$checks[] = new SiteWatchCheck( 'daily-file-checks', array( SiteWatchCheck::class, 'dailyFileChecks' ) );
				$checks[] = new SiteWatchCheck( 'rule-review', array( SiteWatchCheck::class, 'ruleReview' ) );
				$checks[] = new AiReadersCheck( array( AiReadersCheck::class, 'wordpressSnapshot' ) );
				$checks[] = new AiReadinessCheck( array( AiReadinessCheck::class, 'wordpressSnapshot' ) );
				$checks[] = new KnownHolesCheck( array( KnownHolesCheck::class, 'wordpressSnapshot' ) );
				$checks[] = new FollowUpCheck( 'release-files', array( FollowUpCheck::class, 'releaseFiles' ) );
				$checks[] = new FollowUpCheck( 'closed-plugins', array( FollowUpCheck::class, 'closedPlugins' ) );
				$checks[] = new FollowUpCheck( 'public-content', array( FollowUpCheck::class, 'publicContent' ) );
				$checks[] = new LocalCodeCheck();
				$checks[] = new FollowUpCheck( 'suspicious-files', array( FollowUpCheck::class, 'suspiciousFiles' ) );
				$checks[] = new FollowUpCheck( 'local-inventory', array( FollowUpCheck::class, 'localInventory' ) );
				$checks[] = new FollowUpCheck( 'security-headers', array( FollowUpCheck::class, 'securityHeaders' ) );
				return ( new ScanCoordinator() )->run( $checks, new ScanContext() );
			}
		);
		$this->save    = Closure::fromCallable( $save ?? static fn( ScanRun $run ) => ( new FindingsRepository() )->save( $run ) );
	}

	public function run(): ScanRun {
		$run = ( $this->execute )();
		( $this->save )( $run );
		return $run;
	}

	/** @return SecurityCheck[] */
	public static function checks( Values $values, callable $readMode ): array {
		return array( new HttpsAdminCheck( $values ), new UpdatePostureCheck( $values ), new AdminAccountsCheck( $values ), new DebugDisplayCheck( $values ), new FileEditorCheck( $values ), new LoginRateModeCheck( $readMode ) );
	}

	private static function gateOption( string $option ): string {
		$value = get_option( $option, '0' );
		return is_string( $value ) ? $value : '0';
	}
}
