<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Repository;

defined( 'ABSPATH' ) || exit;

final class DirectoryAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified right after validation.
		$key = isset( $_POST['target'] ) && is_string( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : '';
		$fp  = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_key( wp_unslash( $_POST['fingerprint'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		if ( ! preg_match( '/^[a-f0-9]{32}$/D', $key ) || ! preg_match( '/^[a-f0-9]{64}$/D', $fp ) ) {
			wp_die( esc_html__( 'Select a current target and consent to the WordPress.org lookup.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );}
		check_admin_referer( 'ironlatch_repository_' . $key . '_' . $fp );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		$consent = isset( $_POST['consent'] ) && is_string( $_POST['consent'] ) ? sanitize_text_field( wp_unslash( $_POST['consent'] ) ) : '';
		if ( '1' !== $consent ) {
			wp_die( esc_html__( 'Select a current target and consent to the WordPress.org lookup.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );}
		try {
			$result = ( new WordPressDirectoryService() )->create()->lookup( $key, $fp, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( in_array( $result, array( 'changed', 'unsupported' ), true ) ) {
			wp_die( esc_html__( 'The selected plugin changed or is unsupported. Reload the report; no directory result was saved.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) );}
		if ( ! in_array( $result, array( 'saved', 'cached' ), true ) ) {
			wp_die( esc_html__( 'The advisory could not be saved, storage is full or another worker is active. Earlier results remain historical. Ask the host administrator to review the local state.', 'ironlatch-security-scanner' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-repository' ) );
		exit;
	}
}
