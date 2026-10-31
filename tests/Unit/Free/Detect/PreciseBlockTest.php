<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Detect;

use AmazingPlugins\Security\Free\Detect\Module;
use PHPUnit\Framework\TestCase;

final class PreciseBlockTest extends TestCase {
	public function test_option_off_stays_quiet(): void {
		$query = array(
			Module::PROBE_KEY => '1',
			'q'               => Module::VALUE_NEEDLE,
			'union'           => 'UNION SELECT',
			'walk'            => '../',
		);
		foreach ( array( '0', '', 'off', 'true' ) as $option ) {
			self::assertFalse( Module::shouldBlock( $query, $option, false ) );
		}
	}

	public function test_on_blocks_only_the_two_needles(): void {
		self::assertTrue( Module::shouldBlock( array( Module::PROBE_KEY => '1' ), '1', false ) );
		self::assertTrue( Module::shouldBlock( array( 'q' => 'xx' . Module::VALUE_NEEDLE . 'yy' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'q' => 'UNION SELECT' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'q' => '../' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'q' => 'SELECT * FROM posts' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'AMSEC_BLOCK_PROBE' => '1' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'q' => 'amsec_webshell_marker_<?PHP' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( Module::VALUE_NEEDLE => '1' ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 'list' => array( Module::VALUE_NEEDLE ) ), '1', false ) );
		self::assertFalse( Module::shouldBlock( array( 0 => Module::VALUE_NEEDLE ), '1', false ) );
	}

	public function test_disable_flag_wins(): void {
		self::assertFalse( Module::constantDisables() );
		self::assertFalse( Module::shouldBlock( array( Module::PROBE_KEY => '1' ), '1', true ) );
		self::assertFalse( Module::shouldBlock( array( 'q' => Module::VALUE_NEEDLE ), '1', true ) );
	}

	public function test_budget_stops_at_two_kib(): void {
		$late = str_repeat( 'a', 2048 ) . Module::VALUE_NEEDLE;
		self::assertFalse( Module::shouldBlock( array( 'q' => $late ), '1', false ) );
		self::assertFalse(
			Module::shouldBlock(
				array(
					'pad'             => str_repeat( 'b', Module::QUERY_BUDGET ),
					Module::PROBE_KEY => '1',
				),
				'1',
				false
			)
		);
		self::assertTrue( Module::shouldBlock( array( 'q' => Module::VALUE_NEEDLE ), '1', false ) );
	}
}
