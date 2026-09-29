<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Vulnerabilities;

use AmazingPlugins\Security\Vulnerabilities\VersionRangeMatcher;
use PHPUnit\Framework\TestCase;

final class VersionRangeMatcherTest extends TestCase {
	public function test_respects_inclusive_and_exclusive_bounds(): void {
		$matcher = new VersionRangeMatcher();
		$range = array( 'from' => '1.0', 'to' => '2.0', 'from_inclusive' => true, 'to_inclusive' => false );
		self::assertTrue( $matcher->contains( '1.0', $range ) );
		self::assertTrue( $matcher->contains( '1.9.9', $range ) );
		self::assertFalse( $matcher->contains( '2.0', $range ) );
		self::assertFalse( $matcher->contains( '0.9', $range ) );
	}

	public function test_unknown_syntax_and_reversed_bounds_never_pass_or_match(): void {
		$matcher = new VersionRangeMatcher();
		self::assertNull( $matcher->contains( '1.5', array( 'from' => '1.*', 'to' => '2.0', 'from_inclusive' => true, 'to_inclusive' => true ) ) );
		self::assertNull( $matcher->contains( 'vendor-dev', array( 'from' => '*', 'to' => '*', 'from_inclusive' => true, 'to_inclusive' => true ) ) );
		self::assertNull( $matcher->contains( '1.5', array( 'from' => '2.0', 'to' => '1.0', 'from_inclusive' => true, 'to_inclusive' => true ) ) );
		self::assertTrue( $matcher->contains( '1.5', array( 'from' => '*', 'to' => '*', 'from_inclusive' => true, 'to_inclusive' => true ) ) );
	}
}
