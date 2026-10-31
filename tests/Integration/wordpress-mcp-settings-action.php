<?php

// Run with AMSEC_CASE=editor|forged|save and WP-CLI eval-file on a disposable site.
use AmazingPlugins\Security\Admin\McpSettingsAction;

$case = getenv( 'AMSEC_CASE' );
if ( ! in_array( $case, array( 'editor', 'forged', 'save' ), true ) ) {
	throw new RuntimeException( 'Unknown MCP settings test case.' );
}
wp_set_current_user( 'editor' === $case ? 2 : 1 );
$_POST['enabled']     = '1';
$_POST['_wpnonce']    = 'forged' === $case ? 'invalid' : wp_create_nonce( 'amsec_mcp_settings' );
$_REQUEST['_wpnonce'] = $_POST['_wpnonce'];
( new McpSettingsAction() )->save();
