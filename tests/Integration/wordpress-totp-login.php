<?php

// Run with wp eval-file on a disposable site; HTTP login cases are exercised separately.
use AmazingPlugins\Security\Login\TotpAuthentication;

global $wp_filter;
$found = false;
foreach ( $wp_filter['authenticate']->callbacks[30] ?? array() as $callback ) {
	$call = $callback['function'] ?? null;
	if ( is_array( $call ) && $call[0] instanceof TotpAuthentication && 'authenticate' === $call[1] ) {
		$found = true;
	}
}
if ( ! $found ) {
	throw new RuntimeException( 'TOTP authentication filter was not registered after core password checks.' );
}
ob_start();
do_action( 'login_form' );
$html = ob_get_clean();
if ( ! str_contains( $html, 'name="amsec_otp"' ) ) {
	throw new RuntimeException( 'Native login field is missing.' );
}
echo "Native TOTP hook integration passed.\n";
