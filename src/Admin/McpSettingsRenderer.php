<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Admin;

defined( 'ABSPATH' ) || exit;

final class McpSettingsRenderer {
	public function render( bool $enabled, bool $abilitiesAvailable, bool $adapterAvailable, string $actionUrl, string $nonce ): string {
		$status = $enabled ? 'enabled' : 'disabled';
		$html   = '<section id="amsec-mcp" class="amsec-mcp" aria-labelledby="amsec-mcp-title"><h2 id="amsec-mcp-title">AI assistant access</h2><p>MCP is ' . esc_html( $status ) . '. WordPress 6.9 or newer and the official MCP Adapter are required. Your site continues to work without either one.</p>';
		if ( ! $abilitiesAvailable || ! $adapterAvailable ) {
			$html .= '<p role="status">MCP is unavailable here. Install or activate the required WordPress version and MCP Adapter before connecting an assistant.</p>';
		}
		$html .= '<p>When enabled, an authenticated administrator can let an assistant list findings, inspect one finding, start a local hardening scan, and read that scan. The assistant cannot approve or apply a fix.</p>';
		$html .= '<form action="' . esc_url( $actionUrl ) . '" method="post"><input type="hidden" name="action" value="amsec_mcp_settings"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><label for="amsec-mcp-enabled">AI assistant access</label><select id="amsec-mcp-enabled" name="enabled"><option value="0"' . ( $enabled ? '' : ' selected' ) . '>Off</option><option value="1"' . ( $enabled ? ' selected' : '' ) . '>On</option></select><button type="submit" class="button button-secondary">Save MCP setting</button></form></section>';
		return $html;
	}
}
