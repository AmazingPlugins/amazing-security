<?php
if ( ! defined( 'WP_CLI' ) || ! WP_CLI || DB_HOST !== 'amsec-next-db' || ! in_array( DB_NAME, array( 'wordpress', 'wordpress69' ), true ) ) {
	exit( 1 );}
$form = WPCF7_ContactForm::get_template();
$form->set_title( 'AmSec Security Scanner dummy form' );
$form->save();
$product = new WC_Product_Simple();
$product->set_name( 'AmSec Security Scanner dummy product' );
$product->set_regular_price( '5' );
$productId = $product->save();
$page      = wp_insert_post(
	array(
		'post_title'   => 'AmSec Security Scanner compatibility fixture',
		'post_status'  => 'publish',
		'post_type'    => 'page',
		'post_content' => '[contact-form-7 id="' . $form->id() . '"][product_page id="' . $productId . '"]',
	)
);
if ( is_wp_error( $page ) || ! $page ) {
	throw new RuntimeException( 'Frontend fixture failed.' );}
update_option( 'home', 'http://localhost' );
update_option( 'siteurl', 'http://localhost' );
echo (int) $page;
