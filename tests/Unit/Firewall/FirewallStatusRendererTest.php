<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Firewall;

use AmazingPlugins\Security\Firewall\FirewallStatusRenderer;
use PHPUnit\Framework\TestCase;

final class FirewallStatusRendererTest extends TestCase {
	public function test_names_observe_only_rest_coverage_and_escapes_counts(): void {
		$html = ( new FirewallStatusRenderer() )->render( array( 'AS-REST-001' => array( 'count' => 2, 'last_at' => 1000 ) ) );
		self::assertStringContainsString( 'Observe only', $html );
		self::assertStringContainsString( 'REST query', $html );
		self::assertStringContainsString( '2', $html );
		self::assertStringNotContainsString( 'blocked', $html );
	}
}
