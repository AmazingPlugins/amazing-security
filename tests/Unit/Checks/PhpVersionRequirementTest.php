<?php
namespace AmazingPlugins\Security\Tests\Unit\Checks;

use AmazingPlugins\Security\Checks\PhpVersionCheck;
use PHPUnit\Framework\TestCase;

final class PhpVersionRequirementTest extends TestCase {
	protected function tearDown(): void {
		unset( $GLOBALS['required_php_version'] );
	}

	public function test_two_part_requirement_from_wordpress_is_readable(): void {
		$GLOBALS['required_php_version'] = '7.4';
		self::assertSame( 'current', PhpVersionCheck::wordpressKind() );
	}

	public function test_three_part_requirement_still_works_and_old_php_is_flagged(): void {
		$GLOBALS['required_php_version'] = '99.0.0';
		self::assertSame( 'older', PhpVersionCheck::wordpressKind() );
	}

	public function test_garbage_requirement_stays_unknown(): void {
		$GLOBALS['required_php_version'] = 'seven';
		self::assertSame( 'unknown', PhpVersionCheck::wordpressKind() );
	}
}
