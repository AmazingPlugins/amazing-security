<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Network;

use AmazingPlugins\Security\Integrity\WordPressOptions;

final class NetworkHook {
	private bool $checked = false;
	public function handle(): void {
		if ( $this->checked || ( defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL ) ) {
			return;}
		$this->checked = true;
		$options       = new WordPressOptions();
		try {
			$state   = ( new NetworkPolicy() )->read( $options->get( 'amsec_network_policy' ) );
			$address = ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->address( $_SERVER ) ?? '';
			$method  = is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
			$match   = ( new NetworkPolicy() )->matches( $state, $address, $method, current_user_can( 'manage_options' ), defined( 'WP_CLI' ) && WP_CLI, defined( 'DOING_CRON' ) && DOING_CRON );
		} catch ( \Throwable ) {
			return;}
		if ( ! $match ) {
			return;}
		$this->observe( $options, $state['revision'] );
		if ( 'block' === $state['mode'] ) {
			\AmazingPlugins\Security\Traffic\TrafficHooks::mark( 'network-block' );
			wp_die( esc_html__( 'This request is not allowed by the site network policy. Contact the site owner.', 'amazing-security' ), '', array( 'response' => 403 ) );}
	}
	private function observe( WordPressOptions $options, string $revision ): void {
		try {
			( new NetworkObservation( $options ) )->record( $revision, time() );} catch ( \Throwable ) {
			return; /* Advisory counts never decide access. */}
	}
}
