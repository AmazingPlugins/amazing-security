<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Tests\Unit\Activity;

use AmazingPlugins\Security\Activity\ActivityRenderer;
use AmazingPlugins\Security\Activity\ActivityRepository;
use PHPUnit\Framework\TestCase;
final class ActivityRendererTest extends TestCase {
	public function test_stored_values_are_escaped_and_empty_state_is_honest(): void {
		$view = new ActivityRenderer();
		$html = $view->render(
			array(
				array(
					'event'      => '<script>',
					'target'     => '<img onerror=x>',
					'actor_id'   => 1,
					'user_id'    => 2,
					'created_at' => 100,
				),
			),
			1,
			''
		);
		self::assertStringNotContainsString( '<script>', $html );
		self::assertStringContainsString( '&lt;script&gt;', $html );
		self::assertStringNotContainsString( '<img ', $html );
		self::assertStringContainsString( 'No recorded events', $view->render( array(), 1, '' ) );
		self::assertStringContainsString( 'best effort', $html );
	}

	public function test_rows_name_the_account_and_the_change(): void {
		$html = ( new ActivityRenderer() )->render(
			array(
				array(
					'event'      => 'login_succeeded',
					'target'     => '',
					'actor_id'   => 0,
					'user_id'    => 4,
					'created_at' => 1700000000,
				),
				array(
					'event'      => 'user_role_changed',
					'target'     => 'editor',
					'actor_id'   => 0,
					'user_id'    => 3,
					'created_at' => 1700000000,
				),
				array(
					'event'      => 'security_setting_changed',
					'target'     => 'amsec_login_rate_mode',
					'actor_id'   => 1,
					'user_id'    => 0,
					'created_at' => 1700000000,
				),
				array(
					'event'      => 'plugin_activated',
					'target'     => 'amsec-security-scanner/amsec-security-scanner.php',
					'actor_id'   => 0,
					'user_id'    => 0,
					'created_at' => 1700000000,
				),
			),
			2,
			'',
			2
		);
		self::assertStringNotContainsString( 'Actor ID', $html );
		self::assertStringContainsString( 'Previous', $html );
		self::assertStringContainsString( 'Next', $html );
		self::assertStringContainsString( 'Page 2 of 2', $html );
		self::assertStringNotContainsString( 'Newer', $html );
		self::assertStringContainsString( 'Signed in', $html );
		self::assertStringContainsString( 'Account 4', $html );
		self::assertStringContainsString( 'is now Editor', $html );
		self::assertStringContainsString( 'Sign-in limit', $html );
		self::assertStringContainsString( 'AmSec Security Scanner', $html );
		self::assertStringNotContainsString( 'amsec_login_rate_mode', $html );
	}

	public function test_one_page_lists_ten_records(): void {
		self::assertSame( 10, ActivityRepository::PAGE_SIZE );
		self::assertSame( 1, ActivityRepository::pageCount( 10 ) );
		self::assertSame( 9, ActivityRepository::pageCount( 82 ) );
	}
}
