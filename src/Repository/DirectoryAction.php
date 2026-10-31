<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

final class DirectoryAction {
	public function handle(): void {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'amsec-security-scanner' ), '', array( 'response' => 403 ) );}
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact selected-key/fingerprint nonce is checked below before any request.
		$post = wp_unslash( $_POST );
		$key  = is_string( $post['target'] ?? null ) ? $post['target'] : '';
		$fp   = is_string( $post['fingerprint'] ?? null ) ? $post['fingerprint'] : '';
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $key ) || ! preg_match( '/^[a-f0-9]{64}$/D', $fp ) || '1' !== ( $post['consent'] ?? null ) ) {
			wp_die( esc_html__( 'Select a current target and consent to the WordPress.org lookup.', 'amsec-security-scanner' ), '', array( 'response' => 400 ) );}
		check_admin_referer( 'amsec_repository_' . $key . '_' . $fp );
		try {
			$result = ( new WordPressDirectoryService() )->create()->lookup( $key, $fp, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( in_array( $result, array( 'changed', 'unsupported' ), true ) ) {
			wp_die( esc_html__( 'The selected plugin changed or is unsupported. Reload the report; no directory result was saved.', 'amsec-security-scanner' ), '', array( 'response' => 409 ) );}
		if ( ! in_array( $result, array( 'saved', 'cached' ), true ) ) {
			wp_die( esc_html__( 'The advisory could not be saved, storage is full or another worker is active. Earlier results remain historical. Ask the host administrator to review the local state.', 'amsec-security-scanner' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-repository' ) );
		exit;
	}
}
