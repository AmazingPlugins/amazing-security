<?php

// Run with wp eval-file on a disposable current WordPress site with WooCommerce active.
if ( ! class_exists( 'WooCommerce' ) ) {
	throw new RuntimeException( 'WooCommerce is not active.' );
}
ob_start();
do_action( 'woocommerce_login_form' );
$html = ob_get_clean();
if ( ! str_contains( $html, 'name="amsec_otp"' ) ) {
	throw new RuntimeException( 'WooCommerce login field is missing.' );
}
echo "WooCommerce TOTP hook integration passed.\n";
