<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

final class ContentAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and a POST request are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified right after validation.
		$operation = isset( $_POST['operation'] ) && is_string( $_POST['operation'] ) ? sanitize_key( wp_unslash( $_POST['operation'] ) ) : '';
		$id        = isset( $_POST['scan_id'] ) && is_string( $_POST['scan_id'] ) ? sanitize_key( wp_unslash( $_POST['scan_id'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		if ( ! in_array( $operation, array( 'start', 'resume' ), true ) || ( 'resume' === $operation && ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) ) {
			wp_die( esc_html__( 'Invalid scan request.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );
		}
		check_admin_referer( 'start' === $operation ? 'ironlatch_content_start' : 'ironlatch_content_resume_' . $id );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method ) {
			wp_die( esc_html__( 'Administrator access and a POST request are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );
		}
		try {
			$service = ( new WordPressContentService() )->create();
			$result  = 'start' === $operation ? $service->start( time() ) : $service->step( time(), $id );
			if ( 'started' === $result ) {
				$result = $service->step( time() );
			}
		} catch ( \Throwable ) {
			$result = 'failed';
		}
		if ( 'changed' === $result ) {
			wp_die( esc_html__( 'The scan changed. Reload the report before continuing.', 'ironlatch-security-scanner' ), '', array( 'response' => 409 ) ); }
		if ( in_array( $result, array( 'failed', 'busy', 'invalid', 'none' ), true ) ) {
			wp_die( esc_html__( 'The scan could not be saved or another worker is active. Reload the report and retry; no complete coverage is claimed.', 'ironlatch-security-scanner' ), '', array( 'response' => 503 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-content' ) );
		exit;
	}
}
