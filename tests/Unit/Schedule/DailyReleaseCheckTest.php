<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Schedule;

use AmazingPlugins\Security\Schedule\DailyReleaseCheck;
use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use PHPUnit\Framework\TestCase;

final class DailyReleaseCheckTest extends TestCase {
	public function test_the_daily_cycle_skips_the_wordpress_org_step_unless_it_is_on(): void {
		self::assertSame( 'files', DailyReleaseCheck::firstStage( false ) );
		self::assertSame( 'amsec_file_tick', DailyReleaseCheck::firstHook( false ) );
		self::assertSame( 'integrity', DailyReleaseCheck::firstStage( true ) );
		self::assertSame( 'amsec_integrity_tick', DailyReleaseCheck::firstHook( true ) );
	}

	public function test_the_switch_names_the_hosts_and_what_is_sent_and_defaults_to_unchecked(): void {
		$html = ( new ScheduleStatusRenderer() )->renderReleaseToggle( false, '/wp-admin/admin-post.php', 'nonce123' );
		self::assertStringContainsString( 'api.wordpress.org', $html );
		self::assertStringContainsString( 'No file contents are sent', $html );
		self::assertStringContainsString( 'value="amsec_daily_release_check"', $html );
		self::assertStringNotContainsString( 'value="1" checked', $html );
		self::assertStringContainsString( 'value="1" checked', ( new ScheduleStatusRenderer() )->renderReleaseToggle( true, '/x', 'n' ) );
	}

	public function test_the_integrity_tick_and_daily_callback_use_the_switch(): void {
		$root = dirname( __DIR__, 3 );
		self::assertStringContainsString( 'DailyReleaseCheck::enabled()', (string) file_get_contents( $root . '/src/Admin/IntegrityScanAction.php' ) );
		self::assertStringContainsString( 'DailyReleaseCheck::firstStage', (string) file_get_contents( $root . '/amazing-security.php' ) );
	}
}
