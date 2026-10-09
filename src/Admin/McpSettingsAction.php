<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use AmazingPlugins\Security\Mcp\McpPreferences;
use InvalidArgumentException;
use Throwable;

final class McpSettingsAction {
	public static function parse( array $post ): bool {
		$value = $post['enabled'] ?? null;
		if ( ! is_string( $value ) || ! in_array( $value, array( '0', '1' ), true ) ) {
			throw new InvalidArgumentException( 'Invalid MCP setting.' );
		}
		return '1' === $value;
	}

	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot change MCP access.', 'amazing-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'amsec_mcp_settings' );
		try {
			// Nonce verified above.
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$enabled = self::parse( wp_unslash( $_POST ) );
			( new McpPreferences( new WordPressOptions() ) )->setEnabled( $enabled );
		} catch ( Throwable ) {
			wp_die( esc_html__( 'MCP setting could not be saved.', 'amazing-security' ), '', array( 'response' => 400 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-assistant#amsec-mcp' ) );
		exit;
	}
}
