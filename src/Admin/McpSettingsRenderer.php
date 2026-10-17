<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

final class McpSettingsRenderer {
	public function render( bool $enabled, bool $abilitiesAvailable, bool $adapterAvailable, string $actionUrl, string $nonce ): string {
		$status = $enabled ? __( 'enabled', 'amazing-security' ) : __( 'disabled', 'amazing-security' );
		$html   = '<section id="amsec-mcp" class="amsec-mcp" aria-labelledby="amsec-mcp-title"><h2 id="amsec-mcp-title">' . esc_html__( 'AI assistant access', 'amazing-security' ) . '</h2><p>' . sprintf(
				/* translators: %s: current MCP status, either enabled or disabled. */
			esc_html__( 'MCP is %s. WordPress 6.9 or newer and the official MCP Adapter are required. Your site continues to work without either one.', 'amazing-security' ),
			esc_html( $status )
		) . '</p>';
		if ( ! $abilitiesAvailable || ! $adapterAvailable ) {
			$html .= '<p role="status">' . esc_html__( 'MCP is unavailable here. Install or activate the required WordPress version and MCP Adapter before connecting an assistant.', 'amazing-security' ) . '</p>';
		}
		$html .= '<p>' . esc_html__( 'When enabled, an authenticated administrator can let an assistant list findings, inspect one finding, start a local hardening scan, and read that scan. The assistant cannot approve or apply a fix.', 'amazing-security' ) . '</p>';
		$html .= '<form action="' . esc_url( $actionUrl ) . '" method="post"><input type="hidden" name="action" value="amsec_mcp_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><label for="amsec-mcp-enabled">' . esc_html__( 'AI assistant access', 'amazing-security' ) . '</label><select id="amsec-mcp-enabled" name="enabled"><option value="0"' . ( $enabled ? '' : ' selected' ) . '>' . esc_html__( 'Off', 'amazing-security' ) . '</option><option value="1"' . ( $enabled ? ' selected' : '' ) . '>' . esc_html__( 'On', 'amazing-security' ) . '</option></select><button type="submit" class="button button-secondary">' . esc_html__( 'Save MCP setting', 'amazing-security' ) . '</button></form></section>';
		return $html;
	}
}
