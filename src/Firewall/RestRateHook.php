<?php

declare(strict_types=1);
namespace AmazingPlugins\Security\Firewall;

defined( 'ABSPATH' ) || exit;

use AmazingPlugins\Security\Bots\BotCounterStore;
final class RestRateHook {
	private ?RestRateGate $gate = null;
	public function filter( mixed $result, mixed $server, mixed $request ): mixed {
		if ( ( defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL ) || ! $request instanceof \WP_REST_Request ) {
			return $result;}
		try {
			$state      = ( new RestRatePolicy() )->read( get_option( 'amsec_rest_rate_policy', null ) );
			$this->gate = $this->gate ?? new RestRateGate( ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->salt( wp_salt( 'auth' ) ), static fn( string $key, int $window, int $now ): ?int=>( new BotCounterStore( $GLOBALS['wpdb'] ) )->record( $key, $window, $now ) );
			if ( $this->gate->reject( $request, $state, $request->get_route(), $request->get_method(), is_user_logged_in(), $result, ( new \AmazingPlugins\Security\Proxy\WordPressClientAddress() )->server( $_SERVER ), time() ) ) {
				\AmazingPlugins\Security\Traffic\TrafficHooks::mark( 'rest-rate-block' );
				return new \WP_Error( 'amsec_rest_rate', __( 'Too many requests to this endpoint. Retry later or contact the site owner.', 'amazingplugins-security-scanner' ), array( 'status' => 429 ) );}
		} catch ( \Throwable ) {
			return $result;}
		return $result;
	}
}
