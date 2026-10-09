<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Free\TrafficGuard;

use AmazingPlugins\Security\Free\TrafficGuard\HotlinkRule;
use PHPUnit\Framework\TestCase;

final class HotlinkRuleTest extends TestCase {
	public function test_the_rule_allows_this_host_and_can_be_removed(): void {
		$snippet = HotlinkRule::snippet( '127.0.0.1' );
		self::assertStringContainsString( '127\.0\.0\.1', $snippet );
		self::assertStringContainsString( HotlinkRule::BEGIN, $snippet );
		$merged = HotlinkRule::apply( "# Begin Amazing Security uploads\nkeep\n", '127.0.0.1', true );
		self::assertStringContainsString( 'keep', $merged );
		self::assertStringContainsString( HotlinkRule::BEGIN, $merged );
		self::assertSame( "# Begin Amazing Security uploads\nkeep\n", HotlinkRule::apply( $merged, '127.0.0.1', false ) );
	}

	public function test_a_blank_host_does_not_write_a_rule(): void {
		self::assertSame( '', HotlinkRule::apply( '', ' ', true ) );
	}
}
