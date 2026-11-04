<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

final class HeaderAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$s  = ( new WordPressHeaderService() )->create();
		$fp = $s->fingerprint();
		check_admin_referer( 'ironlatch_headers_' . $fp );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method ) {
			wp_die( esc_html__( 'Administrator access and POST required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$posted_fp = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_key( wp_unslash( $_POST['fingerprint'] ) ) : '';
		$consent   = isset( $_POST['consent'] ) && is_string( $_POST['consent'] ) ? sanitize_text_field( wp_unslash( $_POST['consent'] ) ) : '';
		if ( $posted_fp !== $fp || '1' !== $consent ) {
			wp_die( esc_html__( 'Confirm the current homepage assessment and consent.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );}
		try {
			$result = $s->check( $fp, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( ! in_array( $result, array( 'saved', 'cached' ), true ) ) {
			wp_die( esc_html__( 'Assessment was not saved. Review the local state and retry; no new coverage is claimed.', 'ironlatch-security-scanner' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-traffic-guard#headers' ) );
		exit;
	}
}
