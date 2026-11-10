<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Assistant;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\McpSettingsRenderer;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

/** AI & MCP page: the switch for outside AI agent access. */
final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
	}

	public static function menu(): void {
		add_submenu_page(
			'ironlatch-security-scanner',
			__( 'AI & MCP', 'ironlatch-security-scanner' ),
			__( 'AI & MCP', 'ironlatch-security-scanner' ),
			'manage_options',
			'ironlatch-assistant',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$enabled = ( new McpPreferences( new WordPressOptions() ) )->enabled();
		$adapter = function_exists( 'is_plugin_active' ) && is_plugin_active( 'mcp-adapter/mcp-adapter.php' );
		echo '<div class="wrap ironlatch-security-scanner-admin">';
		echo '<p>' . esc_html__( 'Let an outside AI agent review this site\'s scan results. The agent connects through MCP and works with the findings. This plugin does not run an AI model itself, and nothing changes until an administrator approves it.', 'ironlatch-security-scanner' ) . '</p>';
		// The renderer escapes its own values.
		echo wp_kses( ( new McpSettingsRenderer() )->render( $enabled, function_exists( 'wp_register_ability' ), $adapter, admin_url( 'admin-post.php' ), wp_create_nonce( 'ironlatch_mcp_settings' ) ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
		echo '</div>';
	}
}
