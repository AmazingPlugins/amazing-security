<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Admin\StartHere;
use AmazingPlugins\Security\Checks\GapCheck;
use AmazingPlugins\Security\Checks\BackgroundUpdatesCheck;
use AmazingPlugins\Security\Checks\ConfigBackupCheck;
use AmazingPlugins\Security\Checks\DebugLogCheck;
use AmazingPlugins\Security\Checks\ErrorLogCheck;
use AmazingPlugins\Security\Checks\InactivePluginsCheck;
use AmazingPlugins\Security\Checks\LocalCodeCheck;
use AmazingPlugins\Security\Checks\InactiveThemesCheck;
use AmazingPlugins\Security\Checks\UploadsPhpFilesCheck;
use AmazingPlugins\Security\Checks\PackageUpdateCheck;
use AmazingPlugins\Security\Checks\RootExposureCheck;
use AmazingPlugins\Security\Checks\PhpVersionCheck;
use AmazingPlugins\Security\Checks\SampleConfigCheck;
use AmazingPlugins\Security\Checks\LicenseFileCheck;
use AmazingPlugins\Security\Checks\ReadmeFileCheck;
use AmazingPlugins\Security\Hardening\PublicMeta;
use AmazingPlugins\Security\Scan\ScanContext;
use PHPUnit\Framework\TestCase;

final class PublicSurfaceTest extends TestCase {
	public function test_version_and_discovery_gates_stay_off_until_turned_on(): void {
		$version = ( new GapCheck( 'version-tag', static fn(): string => '0' ) )->run( new ScanContext() )[0];
		$hidden  = ( new GapCheck( 'version-tag', static fn(): string => '1' ) )->run( new ScanContext() )[0];
		$links   = ( new GapCheck( 'discovery-links', static fn(): string => '0' ) )->run( new ScanContext() )[0];

		self::assertSame( 'warn', $version->state );
		self::assertStringContainsString( 'does not change', $version->summary );
		self::assertStringNotContainsString( 'safe', $version->summary );
		self::assertSame( 'enable-version-tag', StartHere::control( $version )['operation'] );
		self::assertSame( 'pass', $hidden->state );
		self::assertSame( 'disable-version-tag', StartHere::control( $hidden )['operation'] );
		self::assertSame( 'enable-discovery-links', StartHere::control( $links )['operation'] );
		self::assertStringContainsString( 'does not change', $links->summary );
	}

	public function test_generator_tag_is_removed_only_when_the_owner_turns_it_on(): void {
		$off = new PublicMeta( static fn(): bool => false, static fn(): bool => false );
		$on  = new PublicMeta( static fn(): bool => true, static fn(): bool => false );
		self::assertSame( '<meta name="generator" content="WordPress 6.9" />', $off->generator( '<meta name="generator" content="WordPress 6.9" />' ) );
		self::assertSame( '', $on->generator( '<meta name="generator" content="WordPress 6.9" />' ) );
	}

	public function test_readme_warns_when_present_and_does_not_delete_it(): void {
		$present = ( new ReadmeFileCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$absent  = ( new ReadmeFileCheck( static fn(): string => 'absent' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', ReadmeFileCheck::decide( 'present' ) );
		self::assertSame( 'pass', ReadmeFileCheck::decide( 'absent' ) );
		self::assertSame( 'unknown', ReadmeFileCheck::decide( 'link' ) );
		self::assertSame( 'warn', $present->state );
		self::assertStringContainsString( 'does not delete', $present->summary );
		self::assertStringNotContainsString( 'safe', $present->summary );
		self::assertSame( 'amsec-exposure', StartHere::control( $present )['page'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $present ) );
		self::assertSame( 'pass', $absent->state );
		self::assertNull( StartHere::control( $absent ) );
	}

	public function test_license_warns_when_present_and_does_not_delete_it(): void {
		$present = ( new LicenseFileCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $present->state );
		self::assertStringContainsString( 'license.txt', $present->summary );
		self::assertStringContainsString( 'does not delete', $present->summary );
		self::assertStringNotContainsString( 'safe', $present->summary );
		self::assertSame( 'amsec-exposure', StartHere::control( $present )['page'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $present ) );
	}

	public function test_debug_log_warns_when_present_and_does_not_read_it(): void {
		$present = ( new DebugLogCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$absent  = ( new DebugLogCheck( static fn(): string => 'absent' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $present->state );
		self::assertStringContainsString( 'debug.log', $present->summary );
		self::assertStringContainsString( 'does not read or delete', $present->summary );
		self::assertStringContainsString( 'custom log path is not checked', $present->summary );
		self::assertStringNotContainsString( 'safe', $present->summary );
		self::assertSame( 'amsec-exposure', StartHere::control( $present )['page'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $present ) );
		self::assertSame( 'pass', $absent->state );
		self::assertNull( StartHere::control( $absent ) );
	}

	public function test_root_and_runtime_warnings_do_not_change_the_site(): void {
		$sample = ( new SampleConfigCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$error  = ( new ErrorLogCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$backup = ( new ConfigBackupCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$php    = ( new PhpVersionCheck( static fn(): string => 'older' ) )->run( new ScanContext() )[0];
		$updates = ( new BackgroundUpdatesCheck( static fn(): string => 'off' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $sample->state );
		self::assertStringContainsString( 'does not delete', $sample->summary );
		self::assertStringContainsString( 'does not read or delete', $error->summary );
		self::assertStringContainsString( 'does not read or delete', $backup->summary );
		self::assertStringContainsString( 'does not contact', $php->summary );
		self::assertStringContainsString( 'does not turn them on', $updates->summary );
		foreach ( array( $sample, $error, $backup ) as $row ) {
			self::assertStringNotContainsString( 'safe', $row->summary );
			self::assertSame( 'amsec-exposure', StartHere::control( $row )['page'] );
			self::assertArrayNotHasKey( 'action', StartHere::control( $row ) );
		}
		self::assertStringNotContainsString( 'safe', $php->summary );
		self::assertSame( 'site-health.php', StartHere::control( $php )['screen'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $php ) );
		self::assertStringNotContainsString( 'safe', $updates->summary );
		self::assertSame( 'update-core.php', StartHere::control( $updates )['screen'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $updates ) );
		self::assertSame( 'pass', BackgroundUpdatesCheck::decide( 'on' ) );
		self::assertSame( 'pass', PhpVersionCheck::decide( 'current' ) );
	}

	public function test_package_updates_use_saved_wordpress_data_and_do_not_install(): void {
		$plugins = ( new PackageUpdateCheck( 'plugin-updates', static fn(): string => 'waiting' ) )->run( new ScanContext() )[0];
		$themes  = ( new PackageUpdateCheck( 'theme-updates', static fn(): string => 'current' ) )->run( new ScanContext() )[0];
		$unread  = ( new PackageUpdateCheck( 'plugin-updates', static fn(): string => 'missing' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $plugins->state );
		self::assertStringContainsString( 'does not install', $plugins->summary );
		self::assertStringContainsString( 'does not contact', $plugins->summary );
		self::assertSame( 'update-core.php', StartHere::control( $plugins )['screen'] );
		self::assertSame( 'pass', $themes->state );
		self::assertNull( StartHere::control( $themes ) );
		self::assertSame( 'unknown', $unread->state );
		self::assertStringNotContainsString( 'safe', $plugins->summary );
	}

	public function test_inactive_plugins_and_root_files_do_not_change_the_site(): void {
		$inactive = ( new InactivePluginsCheck( static fn(): string => 'inactive' ) )->run( new ScanContext() )[0];
		$active   = ( new InactivePluginsCheck( static fn(): string => 'active' ) )->run( new ScanContext() )[0];
		$env      = ( new RootExposureCheck( static fn(): string => 'env' ) )->run( new ScanContext() )[0];
		$clear    = ( new RootExposureCheck( static fn(): string => 'absent' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $inactive->state );
		self::assertStringContainsString( 'does not deactivate or delete', $inactive->summary );
		$counted = ( new InactivePluginsCheck( static fn(): string => 'inactive:2' ) )->run( new ScanContext() )[0];
		self::assertStringContainsString( '2 inactive plugins', $counted->summary );
		self::assertSame( 'plugins.php', StartHere::control( $inactive )['screen'] );
		self::assertSame( 'pass', $active->state );
		self::assertNull( StartHere::control( $active ) );
		self::assertSame( 'warn', $env->state );
		self::assertStringContainsString( 'does not read or delete', $env->summary );
		self::assertSame( 'amsec-exposure', StartHere::control( $env )['page'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $env ) );
		self::assertSame( 'pass', $clear->state );
		self::assertSame( 'pass', RootExposureCheck::decide( 'absent' ) );
		self::assertSame( 'warn', RootExposureCheck::decide( 'both' ) );
		$themes = ( new InactiveThemesCheck( static fn(): string => 'inactive' ) )->run( new ScanContext() )[0];
		$php    = ( new UploadsPhpFilesCheck( static fn(): string => 'present' ) )->run( new ScanContext() )[0];
		$clear  = ( new UploadsPhpFilesCheck( static fn(): string => 'absent' ) )->run( new ScanContext() )[0];
		self::assertSame( 'warn', $themes->state );
		self::assertStringContainsString( 'does not switch or delete', $themes->summary );
		$themeCount = ( new InactiveThemesCheck( static fn(): string => 'inactive:1' ) )->run( new ScanContext() )[0];
		self::assertStringContainsString( '1 inactive theme is', $themeCount->summary );
		self::assertSame( 'themes.php', StartHere::control( $themes )['screen'] );
		self::assertSame( 'warn', $php->state );
		self::assertStringContainsString( 'does not open, run, or delete', $php->summary );
		self::assertSame( 'upload.php', StartHere::control( $php )['screen'] );
		self::assertArrayNotHasKey( 'action', StartHere::control( $php ) );
		self::assertSame( 'pass', $clear->state );
		self::assertSame( 'unknown', UploadsPhpFilesCheck::decide( 'partial' ) );
		$running = ( new LocalCodeCheck( static fn(): array => array( 'stored' => 'running', 'found' => 0 ) ) )->run( new ScanContext() )[0];
		$clean   = ( new LocalCodeCheck( static fn(): array => array( 'stored' => 'clean', 'found' => 0 ) ) )->run( new ScanContext() )[0];
		self::assertSame( 'unknown', $running->state );
		self::assertSame( 'running', $running->evidence['stored'] );
		self::assertStringContainsString( 'does not contact', $running->summary );
		self::assertSame( 'pass', $clean->state );
		self::assertStringContainsString( 'does not prove the site is clean', $clean->summary );
		self::assertStringNotContainsString( 'safe', $running->summary );
		$match = ( new LocalCodeCheck(
			static fn(): array => array(
				'stored'  => 'found',
				'found'   => 1,
				'scanned' => 4,
				'matches' => 'plugin.php line 12 AS-PHP-001',
			)
		) )->run( new ScanContext() )[0];
		self::assertStringContainsString( '4 files', $match->summary );
		self::assertStringContainsString( 'plugin.php line 12 AS-PHP-001', $match->summary );
		self::assertStringContainsString( 'does not contact', $match->summary );
		foreach ( array( $inactive, $env, $themes, $php, $clear ) as $row ) {
			self::assertStringNotContainsString( 'safe', $row->summary );
		}
	}
}
