<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Content;

defined( 'ABSPATH' ) || exit;

final class ContentAction {
	public function handle(): void {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and a POST request are required.', 'amazing-security-scanner' ), '', array( 'response' => 403 ) );
		}
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified against the selected action and exact active scan before work.
		$post      = wp_unslash( $_POST );
		$operation = is_string( $post['operation'] ?? null ) ? $post['operation'] : '';
		$id        = is_string( $post['scan_id'] ?? null ) ? $post['scan_id'] : '';
		if ( ! in_array( $operation, array( 'start', 'resume' ), true ) || ( 'resume' === $operation && ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) ) {
			wp_die( esc_html__( 'Invalid scan request.', 'amazing-security-scanner' ), '', array( 'response' => 400 ) );
		}
		check_admin_referer( 'start' === $operation ? 'amsec_content_start' : 'amsec_content_resume_' . $id );
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
			wp_die( esc_html__( 'The scan changed. Reload the report before continuing.', 'amazing-security-scanner' ), '', array( 'response' => 409 ) ); }
		if ( in_array( $result, array( 'failed', 'busy', 'invalid', 'none' ), true ) ) {
			wp_die( esc_html__( 'The scan could not be saved or another worker is active. Reload the report and retry; no complete coverage is claimed.', 'amazing-security-scanner' ), '', array( 'response' => 503 ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-content' ) );
		exit;
	}
}
