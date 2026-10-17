<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Headers;

defined( 'ABSPATH' ) || exit;

final class HeaderAction {
	public function handle(): void {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST required.', 'amazing-security' ), '', array( 'response' => 403 ) );}
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact configured-home nonce checked before network request.
		$post = wp_unslash( $_POST );
		$s    = ( new WordPressHeaderService() )->create();
		$fp   = $s->fingerprint();
		if ( ! is_string( $post['fingerprint'] ?? null ) || $post['fingerprint'] !== $fp || ( $post['consent'] ?? null ) !== '1' ) {
			wp_die( esc_html__( 'Confirm the current homepage assessment and consent.', 'amazing-security' ), '', array( 'response' => 400 ) );}
		check_admin_referer( 'amsec_headers_' . $fp );
		try {
			$result = $s->check( $fp, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( ! in_array( $result, array( 'saved', 'cached' ), true ) ) {
			wp_die( esc_html__( 'Assessment was not saved. Review the local state and retry; no new coverage is claimed.', 'amazing-security' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-headers' ) );
		exit;
	}
}
