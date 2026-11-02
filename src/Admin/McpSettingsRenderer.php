<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

final class McpSettingsRenderer {
	public function render( bool $enabled, bool $abilitiesAvailable, bool $adapterAvailable, string $actionUrl, string $nonce ): string {
		$status = $enabled ? __( 'enabled', 'ironlatch-security-scanner' ) : __( 'disabled', 'ironlatch-security-scanner' );
		$html   = '<section id="ironlatch-mcp" class="ironlatch-mcp" aria-labelledby="ironlatch-mcp-title"><h2 id="ironlatch-mcp-title">' . esc_html__( 'AI assistant access', 'ironlatch-security-scanner' ) . '</h2><p>' . sprintf(
				/* translators: %s: current MCP status, either enabled or disabled. */
			esc_html__( 'MCP is %s. WordPress 6.9 or newer and the official MCP Adapter are required. Your site continues to work without either one.', 'ironlatch-security-scanner' ),
			esc_html( $status )
		) . '</p>';
		if ( ! $abilitiesAvailable || ! $adapterAvailable ) {
			$html .= '<p role="status">' . esc_html__( 'MCP is unavailable here. Install or activate the required WordPress version and MCP Adapter before connecting an assistant.', 'ironlatch-security-scanner' ) . '</p>';
		}
		$html .= '<p>' . esc_html__( 'When enabled, an authenticated administrator can let an assistant list findings, inspect one finding, start a local hardening scan, and read that scan. The assistant cannot approve or apply a fix.', 'ironlatch-security-scanner' ) . '</p>';
		$html .= '<form action="' . esc_url( $actionUrl ) . '" method="post"><input type="hidden" name="action" value="ironlatch_mcp_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><label for="ironlatch-mcp-enabled">' . esc_html__( 'AI assistant access', 'ironlatch-security-scanner' ) . '</label><select id="ironlatch-mcp-enabled" name="enabled"><option value="0"' . ( $enabled ? '' : ' selected' ) . '>' . esc_html__( 'Off', 'ironlatch-security-scanner' ) . '</option><option value="1"' . ( $enabled ? ' selected' : '' ) . '>' . esc_html__( 'On', 'ironlatch-security-scanner' ) . '</option></select><button type="submit" class="button button-secondary">' . esc_html__( 'Save MCP setting', 'ironlatch-security-scanner' ) . '</button></form></section>';
		return $html;
	}
}
