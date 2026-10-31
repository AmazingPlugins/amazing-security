<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Free\Assistant;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Admin\McpSettingsRenderer;
use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;

/** Coming soon. A model that can help fix findings needs an Amazing Plugins server. */
final class Module {
	public static function boot(): void {
		add_action( 'admin_menu', array( self::class, 'menu' ) );
	}

	public static function menu(): void {
		add_submenu_page(
			'amsec-security-scanner',
			__( 'AI & MCP', 'amsec-security-scanner' ),
			__( 'AI & MCP', 'amsec-security-scanner' ),
			'manage_options',
			'amsec-assistant',
			array( self::class, 'render' )
		);
	}

	public static function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );
		}
		$enabled = ( new McpPreferences( new WordPressOptions() ) )->enabled();
		echo '<div class="wrap amsec-security-scanner-admin">';
		echo '<p class="amsec-brief-status"><span class="amsec-pill is-off">' . esc_html__( 'Coming soon', 'amsec-security-scanner' ) . '</span></p>';
		echo '<p>' . esc_html__( 'A model should be able to read a scan and help you fix what it finds. That needs an Amazing Plugins server, so it is not in this version.', 'amsec-security-scanner' ) . '</p>';
		echo '<p>' . esc_html__( 'If that server is required, this may be a paid add-on. The scan, the recommendations, and the other tools stay in this plugin.', 'amsec-security-scanner' ) . '</p>';
		if ( $enabled ) {
			echo '<p>' . esc_html__( 'Assistant access is already on for this site. You can turn it off here.', 'amsec-security-scanner' ) . '</p>';
			$adapter = function_exists( 'is_plugin_active' ) && is_plugin_active( 'mcp-adapter/mcp-adapter.php' );
			// The renderer escapes its own values.
			echo wp_kses( ( new McpSettingsRenderer() )->render( true, function_exists( 'wp_register_ability' ), $adapter, admin_url( 'admin-post.php' ), wp_create_nonce( 'amsec_mcp_settings' ) ), \AmazingPlugins\Security\Admin\AdminHtml::allowed() );
		}
		echo '</div>';
	}
}
