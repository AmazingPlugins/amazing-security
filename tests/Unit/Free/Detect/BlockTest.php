<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\Detect;

use AmazingPlugins\Security\Free\Detect\Block;
use PHPUnit\Framework\TestCase;

final class BlockTest extends TestCase {
	public function test_off_and_disable_constant_stay_quiet(): void {
		$get = array( 'amsec_block_probe' => '1' );
		self::assertFalse( Block::hit( $get, false, false ) );
		self::assertFalse( Block::hit( $get, true, true ) );
	}

	public function test_only_the_two_needles_match(): void {
		self::assertTrue( Block::hit( array( 'amsec_block_probe' => '1' ), true, false ) );
		self::assertTrue( Block::hit( array( 'q' => 'amsec_webshell_marker_<?php' ), true, false ) );
		self::assertFalse( Block::hit( array( 'q' => 'UNION SELECT' ), true, false ) );
		self::assertFalse( Block::hit( array( 'q' => '../wp-config.php' ), true, false ) );
	}
}
