<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

defined( 'ABSPATH' ) || exit;

final class ExposureAction {
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read only to name the nonce action; verified right after validation.
		$alias = isset( $_POST['root'] ) && is_string( $_POST['root'] ) ? sanitize_key( wp_unslash( $_POST['root'] ) ) : '';
		if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) ) {
			wp_die( esc_html__( 'Select a supported local root.', 'ironlatch-security-scanner' ), '', array( 'response' => 400 ) );}
		check_admin_referer( 'ironlatch_exposure_' . $alias );
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'ironlatch-security-scanner' ), '', array( 'response' => 403 ) );}
		try {
			$result = ( new WordPressExposureService() )->create()->scan( $alias, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'The local inventory could not be saved or another worker is active. No new coverage is claimed; review the local state and retry.', 'ironlatch-security-scanner' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=ironlatch-exposure' ) );
		exit;
	}
}
