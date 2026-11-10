<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Tests\Unit;

require_once dirname( __DIR__, 2 ) . '/src/Admin/McpSettingsRenderer.php';

use AmazingPlugins\Security\Admin\McpSettingsRenderer;
use PHPUnit\Framework\TestCase;

/** The AI agent switch must always render, say it is off by default, and name the agent consistently. */
final class McpSettingsRendererTest extends TestCase {
	public function test_the_switch_renders_when_access_is_off_and_mcp_is_unavailable(): void {
		$html = ( new McpSettingsRenderer() )->render( false, false, false, 'https://example.test/wp-admin/admin-post.php', 'nonce123' );

		self::assertStringContainsString( 'name="enabled"', $html );
		self::assertStringContainsString( '<option value="0" selected>', $html );
		self::assertStringContainsString( 'MCP is unavailable here', $html );
		self::assertStringContainsString( 'value="nonce123"', $html );
	}

	public function test_the_on_state_is_selected_and_the_copy_says_agent_never_assistant(): void {
		$html = ( new McpSettingsRenderer() )->render( true, true, true, 'https://example.test/wp-admin/admin-post.php', 'n' );

		self::assertStringContainsString( '<option value="1" selected>', $html );
		self::assertStringNotContainsString( 'unavailable', $html );
		self::assertStringNotContainsStringIgnoringCase( 'assistant', $html );
		self::assertStringContainsString( 'cannot approve or apply it', $html );
	}
}
