<?php

declare(strict_types=1);

namespace AmazingPlugins\Security\Firewall;

use AmazingPlugins\Security\Integrity\WordPressOptions;
use Throwable;

final class RestFirewallHook {
	public function filter( mixed $result, mixed $server, mixed $request ): mixed {
		if ( defined( 'AMSEC_DISABLE_FIREWALL' ) && AMSEC_DISABLE_FIREWALL ) {
			return $result;
		}
		if ( ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		try {
			$firewall = new RestFirewall( new RequestInspector(), new ObservationStore( new WordPressOptions() ) );
			$firewall->observe( $request->get_query_params(), is_user_logged_in(), time() );
		} catch ( Throwable ) {
			// Observation never changes a REST response.
			return $result;
		}
		return $result;
	}
}
