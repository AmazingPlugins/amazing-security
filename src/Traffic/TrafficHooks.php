<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Traffic;

final class TrafficHooks {
	public static function register(): void {
		if ( ( defined( 'AMSEC_DISABLE_TRAFFIC' ) && AMSEC_DISABLE_TRAFFIC ) || ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return; }
		try {
			$policy = ( new TrafficPolicy() )->read( get_option( 'amsec_traffic_policy', null ) );
		} catch ( \Throwable ) {
			return; }
		if ( null === $policy || ! $policy['enabled'] ) {
			return; }
		$server    = array(
			'REQUEST_METHOD' => is_string( $_SERVER['REQUEST_METHOD'] ?? null ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '',
			'SCRIPT_NAME'    => is_string( $_SERVER['SCRIPT_NAME'] ?? null ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '',
		);
		$collector = new TrafficCollector( $policy, $server, false, false );
		add_action(
			'init',
			static function () use ( $collector ): void {
				$collector->identifyAdministrator( current_user_can( 'manage_options' ) );
			},
			1
		);
		add_action( 'amsec_traffic_decision', array( $collector, 'decision' ) );
		add_filter(
			'rest_pre_dispatch',
			static function ( mixed $result, mixed $rest_server, mixed $request ) use ( $collector ): mixed {
				if ( $request instanceof \WP_REST_Request ) {
					$collector->restRoute( $request->get_route() ); }
				return $result;
			},
			1,
			3
		);
		$policyRevision = $policy['revision'];
		add_action(
			'shutdown',
			static function () use ( $collector, $policyRevision ): void {
				try {
					$repository = new TrafficRepository( $GLOBALS['wpdb'] );
					$current    = $repository->currentPolicy();
					$code       = http_response_code();
					$event      = $collector->finish( $current, current_user_can( 'manage_options' ), is_int( $code ) ? $code : 0, time() );
					if ( null !== $event ) {
						$repository->append( $event, $policyRevision ); }
				} catch ( \Throwable ) {
					return; /* Collection never changes responses. */ }
			},
			1
		);
	}
	public static function mark( string $label ): void {
		try {
			do_action( 'amsec_traffic_decision', $label );
		} catch ( \Throwable ) {
			return; /* Logging callbacks must not interrupt security decisions. */ }
	}
}
