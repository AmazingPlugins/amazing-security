<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Alerts;

use AmazingPlugins\Security\Alerts\AlertSettingsRenderer;
use PHPUnit\Framework\TestCase;

final class AlertSettingsRendererTest extends TestCase {
	public function test_shows_switch_and_attempt_status_without_claiming_delivery(): void {
		$html = ( new AlertSettingsRenderer() )->render( true, array( 'last_attempt' => array( 'status' => 'accepted', 'at' => 1000, 'count' => 2 ) ), 'https://example.test/admin-post.php', 'nonce' );
		self::assertStringContainsString( 'Email alerts', $html );
		self::assertStringContainsString( 'Accepted for sending', $html );
		self::assertStringContainsString( 'name="enabled" value="1" checked', $html );
		self::assertStringNotContainsString( 'Delivered', $html );
	}
}
