<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Exposure;

defined( 'ABSPATH' ) || exit;

final class ExposureAction {
	public function handle(): void {
		$method = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'post' !== $method || ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Administrator access and POST are required.', 'amazingplugins-security-scanner' ), '', array( 'response' => 403 ) );}
	 // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixed root-specific nonce is verified before any inventory work.
		$post  = wp_unslash( $_POST );
		$alias = is_string( $post['root'] ?? null ) ? $post['root'] : '';
		if ( ! in_array( $alias, array( 'site', 'content', 'uploads' ), true ) ) {
			wp_die( esc_html__( 'Select a supported local root.', 'amazingplugins-security-scanner' ), '', array( 'response' => 400 ) );}
		check_admin_referer( 'amsec_exposure_' . $alias );
		try {
			$result = ( new WordPressExposureService() )->create()->scan( $alias, time() );
		} catch ( \Throwable ) {
			$result = 'failed';}
		if ( 'saved' !== $result ) {
			wp_die( esc_html__( 'The local inventory could not be saved or another worker is active. No new coverage is claimed; review the local state and retry.', 'amazingplugins-security-scanner' ), '', array( 'response' => 503 ) );}
		wp_safe_redirect( admin_url( 'admin.php?page=amsec-exposure' ) );
		exit;
	}
}
