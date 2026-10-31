<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Guide;

use AmazingPlugins\Security\Free\Guide\Score;
use PHPUnit\Framework\TestCase;

final class ScoreTest extends TestCase {
	public function test_empty_options_score_zero(): void {
		$score = Score::tally( array() );
		self::assertSame( 0, $score['on'] );
		self::assertSame( 9, $score['total'] );
	}

	public function test_idle_and_flags_count_when_on(): void {
		$options = array( 'amsec_idle_minutes' => '30', 'amsec_hotlink' => '1' );
		self::assertSame( 2, Score::tally( $options )['on'] );
	}

	public function test_preset_stays_local(): void {
		$preset = Score::preset( 'shop' );
		self::assertSame( '1', $preset['amsec_login_confirm'] );
		self::assertArrayNotHasKey( 'amsec_common_passwords', $preset );
		self::assertArrayNotHasKey( 'amsec_precise_block', $preset );
		self::assertSame( array(), Score::preset( 'other' ) );
	}
}
