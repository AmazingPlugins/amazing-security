<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Schedule;

use AmazingPlugins\Security\Schedule\ScheduleStatusRenderer;
use PHPUnit\Framework\TestCase;

final class ScheduleStatusRendererTest extends TestCase {
	public function test_missed_and_partial_status_never_claim_a_clean_scan(): void {
		$renderer = new ScheduleStatusRenderer();
		$missed = $renderer->render( array( 'state' => 'missed', 'attempted_at' => 1000, 'next_due' => 87400 ) );
		self::assertStringContainsString( 'Missed', $missed );
		self::assertStringContainsString( 'local hardening', $missed );
		self::assertStringNotContainsString( 'All clear', $missed );
		$partial = $renderer->render( array( 'state' => 'partial', 'attempted_at' => 1000, 'next_due' => 87400 ) );
		self::assertStringContainsString( 'Incomplete', $partial );
	}
}
