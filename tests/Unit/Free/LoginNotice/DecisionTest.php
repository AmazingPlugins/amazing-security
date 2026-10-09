<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\LoginNotice;

use AmazingPlugins\Security\Free\LoginNotice\Decision;
use PHPUnit\Framework\TestCase;

require_once dirname( __DIR__, 4 ) . '/src/Free/LoginNotice/Decision.php';

/**
 * Send or skip decisions. These tests do not bootstrap WordPress or send mail.
 */
final class DecisionTest extends TestCase {
	public function test_gap_is_one_hour(): void {
		self::assertSame( 3600, Decision::GAP );
		self::assertSame( 'amsec_login_email', Decision::OPTION );
	}

	public function test_off_option_skips(): void {
		self::assertSame( 'skip', Decision::decide( '0', true, null, 1_000 ) );
		self::assertSame( 'skip', Decision::decide( 'true', true, null, 1_000 ) );
		self::assertSame( 'skip', Decision::decide( 'yes', true, null, 1_000 ) );
		self::assertSame( 'skip', Decision::decide( '1 ', true, null, 1_000 ) );
	}

	public function test_account_without_manage_options_skips(): void {
		self::assertSame( 'skip', Decision::decide( '1', false, null, 1_000 ) );
		self::assertSame( 'skip', Decision::decide( '1', false, 1, 1_000 + Decision::GAP ) );
	}

	public function test_missing_last_send_sends_once(): void {
		self::assertSame( 'send', Decision::decide( '1', true, null, 1_000 ) );
		self::assertSame( 'send', Decision::decide( '1', true, Decision::lastSent( '' ), 1_000 ) );
		self::assertSame( 'send', Decision::decide( '1', true, Decision::lastSent( '0' ), 1_000 ) );
		self::assertSame( 'send', Decision::decide( '1', true, Decision::lastSent( 0 ), 1_000 ) );
		self::assertSame( 'send', Decision::decide( '1', true, Decision::lastSent( false ), 1_000 ) );
		self::assertNull( Decision::lastSent( '12abc' ) );
		self::assertNull( Decision::lastSent( array() ) );
	}

	public function test_gap_under_3600_skips_and_3600_sends(): void {
		$last = 1_700_000_000;
		self::assertSame( 'skip', Decision::decide( '1', true, $last, $last ) );
		self::assertSame( 'skip', Decision::decide( '1', true, $last, $last + 3599 ) );
		self::assertSame( 'send', Decision::decide( '1', true, $last, $last + 3600 ) );
		self::assertSame( 'send', Decision::decide( '1', true, $last, $last + 3601 ) );
		self::assertSame( 'skip', Decision::decide( '1', true, $last + 50, $last ) );
		self::assertSame( 1_700_000_050, Decision::lastSent( '1700000050' ) );
		self::assertSame( 1_700_000_050, Decision::lastSent( 1_700_000_050 ) );
	}

	public function test_body_is_only_the_site_name_and_utc_time(): void {
		$body = Decision::body( 'Example', 1_700_000_000 );
		self::assertSame( "Example\n2023-11-14 22:13:20 UTC", $body );
		foreach ( array( 'password', 'cookie', 'session', 'token', '127.0.0.1', 'safe' ) as $forbidden ) {
			self::assertStringNotContainsString( $forbidden, strtolower( $body ) );
		}
	}

	public function test_flag_defaults_off(): void {
		self::assertSame( '0', Decision::flag( null ) );
		self::assertSame( '0', Decision::flag( '0' ) );
		self::assertSame( '0', Decision::flag( 1 ) );
		self::assertSame( '0', Decision::flag( 'on' ) );
		self::assertSame( '1', Decision::flag( '1' ) );
	}
}
