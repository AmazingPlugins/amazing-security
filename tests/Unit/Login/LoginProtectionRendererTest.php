<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit\Login;

use AmazingPlugins\Security\Admin\LoginProtectionRenderer;
use AmazingPlugins\Security\Admin\LoginView;
use PHPUnit\Framework\TestCase;

final class LoginProtectionRendererTest extends TestCase {
	public function test_status_and_user_values_are_escaped(): void {
		$view = new LoginView( '/wp-admin/admin-post.php', array( 'settings' => 'nonce', 'begin' => 'nonce', 'disable' => 'nonce', 'regenerate' => 'nonce' ), 'observe', false, false, true, '<script>alert(1)</script>' );
		$html = ( new LoginProtectionRenderer() )->render( $view );
		self::assertStringContainsString( 'Observe only', $html );
		self::assertStringContainsString( '&lt;script&gt;', $html );
		self::assertStringNotContainsString( '<script>', $html );
		self::assertStringContainsString( 'XML-RPC', $html );
		self::assertStringContainsString( 'Set up verification codes', $html );
	}
}
