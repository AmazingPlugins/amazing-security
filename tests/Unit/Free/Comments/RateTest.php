<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Comments;

require_once dirname( __DIR__, 4 ) . '/src/Free/Comments/Rate.php';

use AmazingPlugins\Security\Free\Comments\Rate;
use PHPUnit\Framework\TestCase;

/** Rate tests. They do not bootstrap WordPress or touch the network. */
final class RateTest extends TestCase {
	public function test_the_switch_defaults_off_and_the_gap_is_one_minute(): void {
		self::assertSame( 'amsec_comment_rate', Rate::OPTION );
		self::assertSame( 60, Rate::GAP );
		self::assertSame( '0', Rate::flag( null ) );
		self::assertSame( '1', Rate::flag( '1' ) );
	}

	public function test_the_subject_is_the_account_or_the_email(): void {
		self::assertSame( 'u12', Rate::subject( 12, 'guest@example.com' ) );
		self::assertSame( 'eguest@example.com', Rate::subject( 0, ' Guest@Example.com ' ) );
		self::assertSame( '', Rate::subject( 0, '' ) );
		self::assertSame( '', Rate::subject( 0, 'not-an-email' ) );
	}

	public function test_off_exempt_and_a_full_minute_allow_another_comment(): void {
		self::assertSame( 'allow', Rate::decide( '0', false, 100, 101 ) );
		self::assertSame( 'allow', Rate::decide( '1', true, 100, 101 ) );
		self::assertSame( 'allow', Rate::decide( '1', false, null, 200 ) );
		self::assertSame( 'allow', Rate::decide( '1', false, 100, 160 ) );
		self::assertSame( 'wait', Rate::decide( '1', false, 100, 159 ) );
	}
}
