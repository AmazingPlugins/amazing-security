<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

use AmazingPlugins\Security\Activity\ActivityRenderer;
use AmazingPlugins\Security\Admin\AccountChoice;
use AmazingPlugins\Security\Admin\FirstRun;
use AmazingPlugins\Security\Admin\StartPanel;
use AmazingPlugins\Security\Free\Comments\SpamHold;
use AmazingPlugins\Security\Free\Notices\Notice;
use AmazingPlugins\Security\Hardening\UploadsRule;
use PHPUnit\Framework\TestCase;

final class FirstRunTest extends TestCase {
	public function test_start_steps_name_the_three_moves(): void {
		$steps = implode( ' ', StartPanel::steps() );
		self::assertStringContainsString( 'Run the scan.', $steps );
		self::assertStringContainsString( 'Log In & Register, and from Traffic', $steps );
		self::assertStringContainsString( 'authenticator and passkey status', $steps );
		self::assertStringNotContainsString( 'safe', strtolower( $steps ) );
	}

	public function test_tour_points_at_each_menu_page_and_promises_nothing_runs(): void {
		$steps = FirstRun::steps();
		self::assertCount( 8, $steps );
		self::assertStringContainsString( 'page=amazing-security"', $steps[0]['target'] );
		self::assertStringContainsString( 'does not change anything', $steps[0]['text'] );
	}

	public function test_account_label_shows_the_name_people_see(): void {
		self::assertSame( 'admin (srt-manual-admin)', AccountChoice::label( 'srt-manual-admin', 'admin' ) );
		self::assertSame( 'owner', AccountChoice::label( 'owner', 'owner' ) );
	}

	public function test_spam_hold_remembers_a_hashed_email_and_stays_off(): void {
		$hash = SpamHold::digest( 'Guest@Example.com', 'salt' );
		self::assertSame( '', SpamHold::digest( 'not-an-email', 'salt' ) );
		self::assertSame( 'allow', SpamHold::decide( '0', false, $hash, array( $hash ) ) );
		self::assertSame( 'allow', SpamHold::decide( '1', true, $hash, array( $hash ) ) );
		self::assertSame( 'hold', SpamHold::decide( '1', false, $hash, array( $hash ) ) );
		self::assertSame( array( $hash ), SpamHold::remember( array(), $hash ) );
		self::assertSame( array( $hash ), SpamHold::remember( array( $hash ), $hash ) );
	}

	public function test_event_email_stays_quiet_until_it_is_on(): void {
		self::assertNull( Notice::message( '0', 'administrator', 'owner' ) );
		self::assertSame(
			'An account was given the administrator role: owner.',
			Notice::message( '1', 'administrator', 'owner' )['body']
		);
		self::assertSame(
			'A sign-in was limited by the local repeat check.',
			Notice::message( '1', 'limited', '' )['body']
		);
		self::assertStringNotContainsString( 'safe', strtolower( Notice::message( '1', 'limited', '' )['body'] ) );
	}

	public function test_uploads_rule_is_appended_once(): void {
		$snippet = UploadsRule::snippet();
		self::assertStringContainsString( 'Require all denied', $snippet );
		$merged = UploadsRule::merge( "Options -Indexes\n" );
		self::assertStringContainsString( 'Options -Indexes', $merged );
		self::assertStringContainsString( UploadsRule::BEGIN, $merged );
		self::assertSame( $merged, UploadsRule::merge( $merged ) );
		self::assertSame( $snippet, UploadsRule::merge( '' ) );
	}

	public function test_activity_labels_use_plain_names(): void {
		self::assertSame( 'Signed in', ActivityRenderer::label( 'login_succeeded' ) );
		self::assertSame( 'Sign-in limited', ActivityRenderer::label( 'login_rate_blocked' ) );
		$html = ( new ActivityRenderer() )->render(
			array(
				array(
					'event'      => 'login_succeeded',
					'target'     => 'ok',
					'actor_id'   => 1,
					'user_id'    => 1,
					'created_at' => 100,
				),
			),
			1,
			''
		);
		self::assertStringContainsString( 'Signed in', $html );
		self::assertStringContainsString( 'best effort', $html );
	}
}
